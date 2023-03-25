package server

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	iptables "github.com/coreos/go-iptables/iptables"

	wgctrl "golang.zx2c4.com/wireguard/wgctrl"
	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/gorilla/mux"
)

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
	gatewayIp := NextIP(cidrSubnet)

	// 1.5) Generating the available IPs, excluding those already allocated
	var availableIPs []net.IP
	for ip := NextIP(gatewayIp); ipnet.Contains(ip); ip = NextIP(ip) {
		if !ipnet.Contains(NextIP(ip)) {
			fmt.Println("IP is the broadcast address: " + ip.String())
		} else if !allocatedIPsMap[ip.String()] && ipnet.Contains(NextIP(ip)) {
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

func getenvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getenvOrDefaultInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		parsedValue, err := strconv.Atoi(value)
		if err == nil {
			return parsedValue
		}
	}
	return defaultValue
}

func printUsage(subcommandFlagSet *flag.FlagSet) {
	fmt.Printf("Usage: %s %s [flags]\n", os.Args[0], os.Args[1])
	fmt.Println("\nMandatory flags/environment variables:")
	subcommandFlagSet.VisitAll(func(f *flag.Flag) {
		if f.Name == "private-key" || f.Name == "endpoint" || f.Name == "bearer-token" {
			fmt.Printf("\t-%s\n\t\t %s=<%s>\n", f.Name, f.Usage, f.Name)
		}
	})

	fmt.Println("\nOptional flags/environment variables:")
	subcommandFlagSet.VisitAll(func(f *flag.Flag) {
		if f.Name != "private-key" && f.Name != "endpoint" && f.Name != "h" && f.Name != "help" && f.Name != "bearer-token" {
			fmt.Printf("\t-%s=%s\n\t\t%s\n", f.Name, f.DefValue, f.Usage)
		}
	})

	fmt.Println("\nHelp flags:")
	fmt.Println("  -h, -help: Print help")
}

func Start() {

	//====/ Configuration \=============================================

	subcommandFlagSet := flag.NewFlagSet("server", flag.ExitOnError)

	// Mandatory flags/environment variables
	privateKey := subcommandFlagSet.String("private-key", os.Getenv("WG_PRIVATE_KEY"), "WireGuard private key (WG_PRIVATE_KEY)")
	wgServerEndpoint := subcommandFlagSet.String("endpoint", os.Getenv("WG_ENDPOINT"), "WireGuard server endpoint, ex: '<ip/hostname>:<port>' (WG_ENDPOINT)")
	bearerToken := subcommandFlagSet.String("bearer-token", os.Getenv("BEARER_TOKEN"), "API bearer token (BEARER_TOKEN)")

	// Optional flags/environment variables
	cidr := subcommandFlagSet.String("cidr", getenvOrDefault("CIDR", "10.242.0.0/16"), "CIDR")
	filePath := subcommandFlagSet.String("file-path", getenvOrDefault("FILE_PATH", "/data/ipam.json"), "File path to store IPAM persistence (FILE_PATH))")
	wgInterfaceName := subcommandFlagSet.String("interface-name", getenvOrDefault("WG_INTERFACE_NAME", "wg0"), "WireGuard interface name (WG_INTERFACE_NAME)")
	httpPort := subcommandFlagSet.String("http-port", getenvOrDefault("HTTP_LISTEN_PORT", "8080"), "HTTP listen port (HTTP_LISTEN_PORT)")
	wgPort := subcommandFlagSet.Int("wg-port", getenvOrDefaultInt("WG_LISTEN_PORT", 51820), "WireGuard listen port (WG_LISTEN_PORT)")

	helpFlag := subcommandFlagSet.Bool("h", false, "Print help")
	helpLongFlag := subcommandFlagSet.Bool("help", false, "Print help")

	subcommandFlagSet.Parse(os.Args[2:])

	if *helpFlag || *helpLongFlag {
		printUsage(subcommandFlagSet)
		return
	}

	// Check mandatory variables/flags
	if *privateKey == "" {
		log.Fatal("WG_PRIVATE_KEY is not set")
	}

	if *wgServerEndpoint == "" {
		log.Fatal("WG_ENDPOINT is not set")
	}

	if *bearerToken == "" {
		log.Fatal("BEARER_TOKEN is not set")
	}

	//====/ Transplaneur \==============================================

	transplaneurServer, err := NewTransplaneurServer(*wgInterfaceName, *privateKey, *wgPort, *cidr, *filePath, *wgServerEndpoint)
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
			if token != "Bearer "+*bearerToken {
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
	log.Printf("Starting server on port %s...\n", *httpPort)
	log.Fatal(http.ListenAndServe(":"+*httpPort, api))
}
