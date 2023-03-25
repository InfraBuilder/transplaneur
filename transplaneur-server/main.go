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
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"

	"github.com/vishvananda/netlink"

	iptables "github.com/coreos/go-iptables/iptables"

	wgctrl "golang.zx2c4.com/wireguard/wgctrl"
	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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

	data, _ := json.MarshalIndent(ipam.allocatedIPs, "", "  ")
	ioutil.WriteFile(ipam.filePath, data, 0644)

	return ip.String(), nil
}

type TransplaneurServer struct {
	ipam         *IPAM
	wgClient     *wgctrl.Client
	wgDeviceName string
	wgLink       *netlink.GenericLink
	privateKey   string
	publicKey    string
	listenPort   int
	gatewayIp    string
	endpoint     string
}

func NewTransplaneurServer(wgDeviceName string, privateKey string, listenPort int, cidr string, filePath string, endpoint string) (*TransplaneurServer, error) {

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

	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create wgctrl client: %v", err)
	}

	// Create a new WireGuard interface
	wgLink := netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: wgDeviceName},
		LinkType:  "wireguard",
	}

	wgPrivateKey, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return &TransplaneurServer{
		ipam:         &ipam,
		wgDeviceName: wgDeviceName,
		wgLink:       &wgLink,
		privateKey:   privateKey,
		publicKey:    wgPrivateKey.PublicKey().String(),
		listenPort:   listenPort,
		wgClient:     wgClient,
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

func (ts *TransplaneurServer) GetGatewayPublicKey() string {
	return ts.publicKey
}

func (ts *TransplaneurServer) RegisterClient(pubkey string) (string, error) {

	// Allocate an IP address
	allocatedIp, err := ts.ipam.Register(pubkey)
	if err != nil {
		return "", err
	}

	// Create peer configuration

	wgPublicKey, err := wgtypes.ParseKey(pubkey)
	if err != nil {
		return "", fmt.Errorf("Failed to parse public key: %v", err)
	}

	persistentKeepaliveInterval := time.Duration(25) * time.Second

	peer := wgtypes.PeerConfig{
		PublicKey:                   wgPublicKey,
		ReplaceAllowedIPs:           true,
		AllowedIPs:                  []net.IPNet{{IP: net.ParseIP(allocatedIp), Mask: net.CIDRMask(32, 32)}},
		PersistentKeepaliveInterval: &persistentKeepaliveInterval,
	}

	// Configure the WireGuard interface
	if err := ts.wgClient.ConfigureDevice(ts.wgDeviceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peer},
	}); err != nil {
		return "", fmt.Errorf("failed to configure device: %v for peer %s (%s)", err, allocatedIp, pubkey)
	}

	// Return the allocated IP address
	return allocatedIp, nil
}

func (ts *TransplaneurServer) Initiate() error {
	ts.enableIPForwarding()
	log.Println("IP forwarding enabled")
	ts.natStart()
	log.Println("NAT started")

	peers := make([]wgtypes.PeerConfig, 0, len(ts.ipam.allocatedIPs))
	for pubKeyStr, ipStr := range ts.ipam.allocatedIPs {
		pubKey, err := wgtypes.ParseKey(pubKeyStr)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %v", err)
		}

		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("invalid IP: %s", ipStr)
		}

		persistentKeepaliveInterval := time.Duration(25) * time.Second

		peers = append(peers, wgtypes.PeerConfig{
			PublicKey: pubKey,
			AllowedIPs: []net.IPNet{
				{
					IP:   ip,
					Mask: net.CIDRMask(32, 32),
				},
			},
			PersistentKeepaliveInterval: &persistentKeepaliveInterval,
		})
	}

	// Convert the private key string to a wgtypes.Key
	privateKey, err := wgtypes.ParseKey(ts.privateKey)

	wgConfig := wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &ts.listenPort,
		ReplacePeers: true,
		Peers:        peers,
	}

	// Assuming the interface is already created using OS-specific method
	// e.g., `ip link add dev wg0 type wireguard`

	// Add the interface
	err = netlink.LinkAdd(ts.wgLink)
	if err != nil {
		return fmt.Errorf("Error creating WireGuard interface: %v\n", err)
	}

	// Start the interface
	err = netlink.LinkSetUp(ts.wgLink)
	if err != nil {
		return fmt.Errorf("Error starting WireGuard interface: %v\n", err)
	}

	// 1.1) Parse the CIDR
	_, ipnet, err := net.ParseCIDR(ts.ipam.cidr)
	if err != nil {
		return fmt.Errorf("Error parsing CIDR: %v\n", err)
	}

	// Create an Addr object
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   net.ParseIP(ts.gatewayIp),
			Mask: ipnet.Mask,
		},
	}

	// Add the IP address to the interface
	err = netlink.AddrAdd(ts.wgLink, addr)
	if err != nil {
		return fmt.Errorf("Error adding IP address: %v\n", err)
	}

	// Configure the wireguard interface
	err = ts.wgClient.ConfigureDevice(ts.wgDeviceName, wgConfig)
	if err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %v", err)
	}

	log.Println("WireGuard configured")

	return nil
}

func (ts *TransplaneurServer) Shutdown() error {
	ts.natStop()
	log.Println("NAT stopped")

	err := netlink.LinkDel(ts.wgLink)
	if err != nil {
		return fmt.Errorf("Error stopping WireGuard interface: %v\n", err)
	}

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

type RegisterRequest struct {
	PublicKey string `json:"publickey"`
}

type RegisterResponse struct {
	ClientIP         string `json:"client_ip"`
	GatewayIP        string `json:"gateway_ip"`
	Endpoint         string `json:"endpoint"`
	GatewayPublicKey string `json:"gateway_public_key"`
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
		GatewayIP:        ts.GetGatewayIP(),
		ClientIP:         ip,
		Endpoint:         ts.GetEndpoint(),
		GatewayPublicKey: ts.GetGatewayPublicKey(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func main() {
	//====/ Configuration \=============================================

	// Mandatory environment variables
	privateKey := os.Getenv("WG_PRIVATE_KEY")
	if privateKey == "" {
		log.Fatal("WG_PRIVATE_KEY is not set")
	}

	wgServerEndpoint := os.Getenv("WG_ENDPOINT")
	if privateKey == "" {
		log.Fatal("WG_ENDPOINT is not set")
	}

	// Optional environment variables
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

	httpPort := "8080"
	if os.Getenv("HTTP_LISTEN_PORT") != "" {
		httpPort = os.Getenv("HTTP_LISTEN_PORT")
	}

	wgPort := 51820
	if os.Getenv("WG_LISTEN_PORT") != "" {
		parsedWgPort, err := strconv.Atoi(os.Getenv("WG_LISTEN_PORT"))
		if err != nil {
			log.Fatal(err)
		} else {
			wgPort = parsedWgPort
		}
	}

	//====/ Transplaneur \==============================================

	transplaneurServer, err := NewTransplaneurServer(wgInterfaceName, privateKey, wgPort, cidr, filePath, wgServerEndpoint)
	if err != nil {
		log.Fatal(err)
	}

	//Initialize IPAM, wireguard, etc.
	err = transplaneurServer.Initiate()
	if err != nil {
		log.Fatal(err)
	}

	//====/ Signal handling \============================================

	// Create a channel to receive the signals
	signalChan := make(chan os.Signal, 1)

	// Register the signals to be caught
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Start a goroutine to handle the signals
	go func() {
		sig := <-signalChan
		fmt.Printf("\nReceived signal: %s\n", sig)

		// Perform your clean-up action here
		fmt.Println("Performing clean-up...")

		transplaneurServer.Shutdown()

		// Exit the program
		os.Exit(0)
	}()

	//====/ HTTP API \======================================================

	// Create API server
	api := mux.NewRouter()

	// Check bearer as middleware
	api.Use(func(next http.Handler) http.Handler {
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
	api.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("%s %s %s %s %s", r.RemoteAddr, r.Method, r.URL, r.Proto, r.UserAgent())
			next.ServeHTTP(w, r)
		})
	})

	// Endpoint to register a new peer
	api.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		httpPostRegister(transplaneurServer, w, r)
	}).Methods("POST")

	// Start API server
	log.Printf("Starting server on port %s...\n", httpPort)
	log.Fatal(http.ListenAndServe(":"+httpPort, api))

}
