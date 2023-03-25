package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"

	"github.com/gorilla/mux"

	iptables "github.com/coreos/go-iptables/iptables"
)

type IPAM struct {
	cidr         string
	allocatedIPs map[string]string
	availableIPs []net.IP
	filePath     string
	mu           sync.Mutex
}

func (ipam *IPAM) String() string {
	return fmt.Sprintf("IPAM(%s) : availableIPs=%d : allocatedIPs=%d", ipam.cidr, len(ipam.availableIPs), len(ipam.allocatedIPs))
}

func (ipam *IPAM) Register(publicKey string) (string, error) {
	ipam.mu.Lock()
	defer ipam.mu.Unlock()

	if ip, ok := ipam.allocatedIPs[publicKey]; ok {
		fmt.Println("pubkey=" + publicKey + " : IP already allocated : " + ip)
		return ip, nil
	}

	if len(ipam.availableIPs) == 0 {
		return "", fmt.Errorf("no IP addresses available")
	}

	ip := ipam.availableIPs[0]
	ipam.availableIPs = ipam.availableIPs[1:]
	ipam.allocatedIPs[publicKey] = ip.String()

	data, _ := json.Marshal(ipam.allocatedIPs)
	ioutil.WriteFile(ipam.filePath, data, 0644)

	return ip.String(), nil
}

type TransplaneurServer struct {
	ipam         *IPAM
	wgDeviceName string
	gatewayIp    string
	endpoint     string
}

func NewTransplaneurServer(wgDeviceName string, cidr string, filePath string, endpoint string) (*TransplaneurServer, error) {

	// === 1) Create the IPAM and set server IP ============================

	// 1.1) Parse the CIDR
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// 1.2) Reading the allocated IPs from the file
	allocatedIPs := make(map[string]string)
	data, err := ioutil.ReadFile(filePath)
	if err == nil {
		json.Unmarshal(data, &allocatedIPs)
	}

	// 1.3) Generate a map to optimize the search of allocated IPs
	allocatedIPsMap := make(map[string]bool)
	for _, ip := range allocatedIPs {
		allocatedIPsMap[ip] = true
	}

	cidrSubnet := ip.Mask(ipnet.Mask)
	gatewayIp := nextIP(cidrSubnet)

	// 1.5) Generating the available IPs, excluding those already allocated
	var availableIPs []net.IP
	for ip := nextIP(gatewayIp); ipnet.Contains(ip); ip = nextIP(ip) {
		if !ipnet.Contains(nextIP(ip)) {
			fmt.Println("IP is the broadcast address: " + ip.String())
		} else if !allocatedIPsMap[ip.String()] && ipnet.Contains(nextIP(ip)) {
			availableIPs = append(availableIPs, ip)
		} else {
			fmt.Println("IP already allocated: " + ip.String())
		}
	}

	// 1.6 Create the IPAM
	ipam := IPAM{
		cidr:         cidr,
		allocatedIPs: allocatedIPs,
		availableIPs: availableIPs,
		filePath:     filePath,
	}

	log.Println("IPAM created: " + ipam.String())

	// === 2) Create the Transplaneur server ===============================

	return &TransplaneurServer{
		ipam:         &ipam,
		wgDeviceName: wgDeviceName,
		gatewayIp:    gatewayIp.String(),
		endpoint:     endpoint,
	}, nil
}

func (ts *TransplaneurServer) GetGatewayIP() string {
	return ts.gatewayIp
}

func (ts *TransplaneurServer) GetEndpoint() string {
	return ts.endpoint
}

func (ts *TransplaneurServer) RegisterClient(pubkey string) (string, error) {
	return ts.ipam.Register(pubkey)
}

func (ts *TransplaneurServer) Initiate() error {
	ts.enableIPForwarding()
	ts.natStart()
	return nil
}

func (ts *TransplaneurServer) Shutdown() error {
	ts.natStop()
	return nil
}

func (ts *TransplaneurServer) enableIPForwarding() error {
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v\nOutput: %s", err, output)
	}

	return nil
}

func (ts *TransplaneurServer) natStart() error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("failed to create iptables instance: %v", err)
	}

	// Accept to act as a router
	err = ipt.AppendUnique("filter", "FORWARD", "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("failed to add FORWARD rule: %v", err)
	}

	// Nat traffic from the VPN that is not destined for the VPN (i.e. exit the VPN)
	err = ipt.AppendUnique("nat", "POSTROUTING", "-s", ts.ipam.cidr, "!", "-d", ts.ipam.cidr, "-j", "MASQUERADE")
	if err != nil {
		return fmt.Errorf("failed to add POSTROUTING rule: %v", err)
	}

	return nil
}

func (ts *TransplaneurServer) natStop() error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("failed to create iptables instance: %v", err)
	}

	// Remove the NAT rule
	err = ipt.Delete("nat", "POSTROUTING", "-s", ts.ipam.cidr, "!", "-d", ts.ipam.cidr, "-j", "MASQUERADE")
	if err != nil {
		return fmt.Errorf("failed to remove POSTROUTING rule: %v", err)
	}

	// Remove the FORWARD rule
	err = ipt.Delete("filter", "FORWARD", "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("failed to remove FORWARD rule: %v", err)
	}

	return nil
}

func nextIP(ip net.IP) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += 1
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)

	return net.IPv4(v0, v1, v2, v3)
}

// type WireGuardInterface struct {
// 	deviceName string
// 	client     *wgctrl.Client
// 	ipam       *IPAM
// }

// func NewWireGuardInterface(deviceName string, ipam *IPAM) (*WireGuardInterface, error) {
// 	client, err := wgctrl.New()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create wgctrl client: %v", err)
// 	}

// 	return &WireGuardInterface{
// 		deviceName: deviceName,
// 		client:     client,
// 		ipam:       ipam,
// 	}, nil
// }

// func (wgi *WireGuardInterface) Initiate() error {
// 	// Assuming the interface is already created using OS-specific method
// 	// e.g., `ip link add dev wg0 type wireguard`

// 	peers, err := wgi.buildPeers()
// 	if err != nil {
// 		return fmt.Errorf("failed to build peers: %v", err)
// 	}

// 	config := wgtypes.Config{
// 		ReplacePeers: true,
// 		Peers:        peers,
// 	}

// 	return wgi.client.ConfigureDevice(wgi.deviceName, config)
// }

// func (wgi *WireGuardInterface) buildPeers() ([]wgtypes.PeerConfig, error) {
// 	wgi.ipam.mu.Lock()
// 	defer wgi.ipam.mu.Unlock()

// 	peers := make([]wgtypes.PeerConfig, 0, len(wgi.ipam.allocatedIPs))

// 	for pubKeyStr, ipStr := range wgi.ipam.allocatedIPs {
// 		pubKey, err := wgtypes.ParseKey(pubKeyStr)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to parse public key: %v", err)
// 		}

// 		ip := net.ParseIP(ipStr)
// 		if ip == nil {
// 			return nil, fmt.Errorf("invalid IP: %s", ipStr)
// 		}

// 		peers = append(peers, wgtypes.PeerConfig{
// 			PublicKey: pubKey,
// 			AllowedIPs: []net.IPNet{
// 				{
// 					IP:   ip,
// 					Mask: net.CIDRMask(32, 32),
// 				},
// 			},
// 			PersistentKeepaliveInterval: time.Duration(25 * time.Second),
// 		})
// 	}

// 	return peers, nil
// }

// func (wgi *WireGuardInterface) Shutdown() error {
// 	// Assuming you remove the interface using OS-specific method
// 	// e.g., `ip link del dev wg0`

// 	return wgi.client.Close()
// }

// func (wgi *WireGuardInterface) AddPeer(pubKeyStr string, ipStr string) error {
// 	pubKey, err := wgtypes.ParseKey(pubKeyStr)
// 	if err != nil {
// 		return fmt.Errorf("failed to parse public key: %v", err)
// 	}

// 	ip := net.ParseIP(ipStr)
// 	if ip == nil {
// 		return fmt.Errorf("invalid IP: %s", ipStr)
// 	}

// 	peerConfig := wgtypes.PeerConfig{
// 		PublicKey: pubKey,
// 		AllowedIPs: []net.IPNet{
// 			{
// 				IP:   ip,
// 				Mask: net.CIDRMask(32, 32),
// 			},
// 		},
// 		PersistentKeepaliveInterval: time.Duration(25 * time.Second),
// 	}

// 	err = wgi.client.ConfigureDevice(wgi.deviceName, wgtypes.Config{
// 		ReplacePeers: false,
// 		Peers:        []wgtypes.PeerConfig{peerConfig},
// 	})

// 	if err == nil {
// 		wgi.ipam.mu.Lock()
// 		wgi.ipam.allocatedIPs[pubKeyStr] = ipStr
// 		wgi.ipam.mu.Unlock()
// 	}

// 	return err
// }

// func (wgi *WireGuardInterface) RemovePeer(pubKeyStr string) error {
// 	pubKey, err := wgtypes.ParseKey(pubKeyStr)
// 	if err != nil {
// 		return fmt.Errorf("failed to parse public key: %v", err)
// 	}

// 	peerConfig := wgtypes.PeerConfig{
// 		PublicKey: pubKey,
// 		Remove:    true,
// 	}

// 	err = wgi.client.ConfigureDevice(wgi.deviceName, wgtypes.Config{
// 		ReplacePeers: false,
// 		Peers:        []wgtypes.PeerConfig{peerConfig},
// 	})

// 	if err == nil {
// 		wgi.ipam.mu.Lock()
// 		ipStr, ok := wgi.ipam.allocatedIPs[pubKeyStr]
// 		if ok {
// 			delete(wgi.ipam.allocatedIPs, pubKeyStr)
// 			wgi.ipam.availableIPs = append(wgi.ipam.availableIPs, net.ParseIP(ipStr))
// 		}
// 		wgi.ipam.mu.Unlock()
// 	}

// 	return err
// }

type RegisterRequest struct {
	PublicKey string `json:"publickey"`
}

type RegisterResponse struct {
	ClientIP  string `json:"client_ip"`
	GatewayIP string `json:"gateway_ip"`
	Endpoint  string `json:"endpoint"`
}

func httpPostRegister(ts *TransplaneurServer, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	ip, err := ts.RegisterClient(req.PublicKey)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	res := RegisterResponse{
		GatewayIP: ts.GetGatewayIP(),
		ClientIP:  ip,
		Endpoint:  ts.GetEndpoint(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func main() {
	//====/ Configuration \=============================================

	// Retrieve configuration from environment variables
	cidr := "10.242.0.0/16"
	if os.Getenv("CIDR") != "" {
		cidr = os.Getenv("CIDR")
	}

	filePath := "/data/ipam.json"
	if os.Getenv("FILE_PATH") != "" {
		filePath = os.Getenv("FILE_PATH")
	}

	wgInterfaceName := "wg0"
	if os.Getenv("WG_INTERFACE_NAME") != "" {
		wgInterfaceName = os.Getenv("WG_INTERFACE_NAME")
	}

	port := "8080"
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}

	//====/ Transplaneur \==============================================

	transplaneurServer, err := NewTransplaneurServer(wgInterfaceName, cidr, filePath, "")
	if err != nil {
		log.Fatal(err)
	}

	transplaneurServer.Initiate()

	//====/ HTTP API \======================================================

	// Create API server
	r := mux.NewRouter()

	// Check bearer as middleware
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			if token != "Bearer "+os.Getenv("BEARER_TOKEN") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// Log requests as middleware
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("%s %s %s %s %s", r.RemoteAddr, r.Method, r.URL, r.Proto, r.UserAgent())
			next.ServeHTTP(w, r)
		})
	})

	// Endpoint to register a new peer
	r.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		httpPostRegister(transplaneurServer, w, r)
	}).Methods("POST")

	// Start API server
	log.Printf("Starting server on port %s...\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
