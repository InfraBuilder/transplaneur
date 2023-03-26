package gateway

import (
	"bytes"
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

	server "github.com/infrabuilder/transplaneur/server"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/gorilla/mux"
)

const (
	sidecarCommunicationDirectory = "/var/run/transplaneur"
)

type TransplaneurGatewayConfig struct {
	GatewayId      string
	WgDeviceName   string
	ApiEndpoint    string
	BearerToken    string
	ClusterPodCidr string
	ClusterSvcCidr string
}

type TransplaneurGateway struct {
	gatewayId        string
	wgClient         *wgctrl.Client
	wgDeviceName     string
	wgLink           *netlink.GenericLink
	privateKey       string
	publicKey        string
	clientIp         string
	gatewayIp        string
	gatewayPublicKey string
	apiEndpoint      string
	endpoint         string
	clusterPodCidr   string
	clusterSvcCidr   string
}

func registerOnServer(apiEndpoint string, publicKey string, bearerToken string) (*server.RegisterResponse, error) {

	requestBody := &server.RegisterRequest{PublicKey: publicKey}
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", apiEndpoint+"/register", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+bearerToken)
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var registerResponse server.RegisterResponse
	err = json.Unmarshal(body, &registerResponse)
	if err != nil {
		return nil, err
	}

	return &registerResponse, nil
}

func NewTransplaneurGateway(config TransplaneurGatewayConfig) (*TransplaneurGateway, error) {

	// create files on communication channel
	err := os.MkdirAll(sidecarCommunicationDirectory+"/"+config.GatewayId, 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create transplaneur directory: %v", err)
	}

	privateKey := ""
	// Read private key from file private_key
	contentBytes, err := ioutil.ReadFile(sidecarCommunicationDirectory + "/" + config.GatewayId + "/private_key")
	if err != nil {
		log.Println("Failed to read private key from file, generating new one")
		// Generate private key
		wgPrivateKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %v", err)
		}

		privateKey = wgPrivateKey.String()
		// Write private key to file private_key
		err = ioutil.WriteFile(sidecarCommunicationDirectory+"/"+config.GatewayId+"/private_key", []byte(privateKey), 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to write private key to file: %v", err)
		}
	} else {
		log.Println("Reading private key from file")
		privateKey = string(contentBytes)
	}

	// Parse private key
	wgPrivateKey, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	// Get public key
	publicKey := wgPrivateKey.PublicKey().String()

	// Fetch config from API server
	registerResponse, err := registerOnServer(config.ApiEndpoint, publicKey, config.BearerToken)
	if err != nil {
		return nil, err
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create wgctrl client: %v", err)
	}

	// Create a new WireGuard interface
	wgLink := netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: config.WgDeviceName},
		LinkType:  "wireguard",
	}

	return &TransplaneurGateway{
		gatewayId:        config.GatewayId,
		wgDeviceName:     config.WgDeviceName,
		wgClient:         wgClient,
		wgLink:           &wgLink,
		privateKey:       privateKey,
		publicKey:        publicKey,
		clientIp:         registerResponse.ClientIP,
		gatewayIp:        registerResponse.GatewayIP,
		gatewayPublicKey: registerResponse.GatewayPublicKey,
		apiEndpoint:      config.ApiEndpoint,
		endpoint:         registerResponse.Endpoint,
		clusterPodCidr:   config.ClusterPodCidr,
		clusterSvcCidr:   config.ClusterSvcCidr,
	}, nil
}

func (tg *TransplaneurGateway) String() string {
	return fmt.Sprintf("TransplaneurGateway(%s) : clientIP=%s, gatewayIP=%s, endpoint=%s", tg.wgDeviceName, tg.clientIp, tg.gatewayIp, tg.endpoint)
}

func (tg *TransplaneurGateway) enableIPForwarding() error {
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v\nOutput: %s", err, output)
	}

	return nil
}

func (tg *TransplaneurGateway) natStart() error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("failed to create iptables instance: %v", err)
	}

	// Accept to act as a router
	err = ipt.AppendUnique("filter", "FORWARD", "-j", "ACCEPT")
	if err != nil {
		return fmt.Errorf("failed to add FORWARD rule: %v", err)
	}

	// Nat traffic going through the VPN
	err = ipt.AppendUnique("nat", "POSTROUTING", "-o", tg.wgDeviceName, "-j", "MASQUERADE")
	if err != nil {
		return fmt.Errorf("failed to add POSTROUTING rule: %v", err)
	}

	return nil
}

func (tg *TransplaneurGateway) natStop() error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("failed to create iptables instance: %v", err)
	}

	// Remove the POSTROUTING rule
	err = ipt.Delete("nat", "POSTROUTING", "-o", tg.wgDeviceName, "-j", "MASQUERADE")
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

func (tg *TransplaneurGateway) Initiate() error {
	if tg.enableIPForwarding() != nil {
		return fmt.Errorf("failed to enable IP forwarding")
	}
	log.Println("IP forwarding enabled")
	if tg.natStart() != nil {
		return fmt.Errorf("failed to start NAT")
	}
	log.Println("NAT started")

	// generate a wg-quick config file
	wgQuickConfig := fmt.Sprintf(`# Generated by transplaneur
[Interface]
PrivateKey = %s
Address = %s/32
DNS = 1.1.1.1

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0, %s/32
Endpoint = %s
PersistentKeepalive = 25
`, tg.privateKey, tg.clientIp, tg.gatewayPublicKey, tg.gatewayIp, tg.endpoint)

	// Write the config file to disk
	fileName := fmt.Sprintf("/etc/wireguard/%s.conf", tg.wgDeviceName)
	err := ioutil.WriteFile(fileName, []byte(wgQuickConfig), 0644)
	if err != nil {
		return fmt.Errorf("failed to write WireGuard config file: %v", err)
	}

	// Call wg-quick up
	cmd := exec.Command("wg-quick", "up", tg.wgDeviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start WireGuard interface: %v\nOutput: %s", err, output)
	}

	// Detect the pod IP address on eth0
	localPodIp, err := getPodLocalIP()
	if err != nil {
		return fmt.Errorf("failed to detect pod IP address: %v", err)
	}

	// Write the config file to disk for sidecars
	if ioutil.WriteFile(sidecarCommunicationDirectory+"/"+tg.gatewayId+"/local-gateway", []byte(localPodIp.String()), 0644) != nil {
		return fmt.Errorf("failed to write local-gateway file")
	}

	if ioutil.WriteFile(sidecarCommunicationDirectory+"/"+tg.gatewayId+"/cluster-pod-cidr", []byte(tg.clusterPodCidr), 0644) != nil {
		return fmt.Errorf("failed to write cluster-pod-cidr file")
	}
	if ioutil.WriteFile(sidecarCommunicationDirectory+"/"+tg.gatewayId+"/cluster-svc-cidr", []byte(tg.clusterSvcCidr), 0644) != nil {
		return fmt.Errorf("failed to write cluster-svc-cidr file")
	}

	log.Println("WireGuard configured")

	return nil
}

func (tg *TransplaneurGateway) Shutdown() error {

	// Delete the config file for sidecars
	os.Remove(sidecarCommunicationDirectory + "/" + tg.gatewayId + "/local-gateway")
	os.Remove(sidecarCommunicationDirectory + "/" + tg.gatewayId + "/cluster-pod-cidr")
	os.Remove(sidecarCommunicationDirectory + "/" + tg.gatewayId + "/cluster-svc-cidr")

	tg.natStop()
	log.Println("NAT stopped")

	// Call wg-quick down
	cmd := exec.Command("wg-quick", "down", tg.wgDeviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop WireGuard interface: %v\nOutput: %s", err, output)
	}

	return nil
}

func getPodLocalIP() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Name == "eth0" {
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, err
			}

			for _, addr := range addrs {
				ip, _, err := net.ParseCIDR(addr.String())
				if err != nil {
					return nil, err
				}

				// We only want IPv4 addresses
				if ip.To4() != nil {
					return ip, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("eth0 interface not found or has no IPv4 address")
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

var mandatoryFlags = map[string]bool{
	"private-key":      true,
	"apiEndpoint":      true,
	"bearer-token":     true,
	"cluster-pod-cidr": true,
	"cluster-svc-cidr": true,
}

func printUsage(subcommandFlagSet *flag.FlagSet) {
	fmt.Printf("Usage: %s %s [flags]\n", os.Args[0], os.Args[1])
	fmt.Println("\nMandatory flags/environment variables:")
	subcommandFlagSet.VisitAll(func(f *flag.Flag) {
		if mandatoryFlags[f.Name] {
			fmt.Printf("\t-%s=<%s>\n\t\t %s\n", f.Name, f.Name, f.Usage)
		}
	})

	fmt.Println("\nOptional flags/environment variables:")
	subcommandFlagSet.VisitAll(func(f *flag.Flag) {
		if !mandatoryFlags[f.Name] && f.Name != "h" && f.Name != "help" {
			fmt.Printf("\t-%s=%s\n\t\t%s\n", f.Name, f.DefValue, f.Usage)
		}
	})

	fmt.Println("\nHelp flags:")
	fmt.Println("  -h, -help: Print help")
}

func Start() {

	//====/ Configuration \=============================================

	subcommandFlagSet := flag.NewFlagSet("gateway", flag.ExitOnError)

	// Mandatory flags/environment variables
	apiEndpoint := subcommandFlagSet.String("apiEndpoint", os.Getenv("API_ENDPOINT"), "Transplaneur API endpoint, ex: '<ip/hostname>:<port>' (API_ENDPOINT)")
	bearerToken := subcommandFlagSet.String("bearer-token", os.Getenv("BEARER_TOKEN"), "API bearer token (BEARER_TOKEN)")
	clusterPodCidr := subcommandFlagSet.String("cluster-pod-cidr", os.Getenv("CLUSTER_POD_CIDR"), "Cluster CIDR for Pods (CLUSTER_POD_CIDR)")
	clusterSvcCidr := subcommandFlagSet.String("cluster-svc-cidr", os.Getenv("CLUSTER_SVC_CIDR"), "Cluster CIDR for Services (CLUSTER_SVC_CIDR)")

	// Optional flags/environment variables
	wgInterfaceName := subcommandFlagSet.String("interface-name", getenvOrDefault("WG_INTERFACE_NAME", "wg0"), "WireGuard interface name (WG_INTERFACE_NAME)")
	httpPort := subcommandFlagSet.String("http-port", getenvOrDefault("HTTP_LISTEN_PORT", "8080"), "HTTP listen port (HTTP_LISTEN_PORT)")
	gatewayId := subcommandFlagSet.String("gateway-id", getenvOrDefault("GATEWAY_ID", "default"), "Identifier for this gateway (GATEWAY_ID)")

	helpFlag := subcommandFlagSet.Bool("h", false, "Print help")
	helpLongFlag := subcommandFlagSet.Bool("help", false, "Print help")

	subcommandFlagSet.Parse(os.Args[2:])

	if *helpFlag || *helpLongFlag {
		printUsage(subcommandFlagSet)
		return
	}

	// Check mandatory variables/flags
	if *apiEndpoint == "" {
		log.Fatal("API_ENDPOINT is not set")
	}

	if *bearerToken == "" {
		log.Fatal("BEARER_TOKEN is not set")
	}
	if *clusterPodCidr == "" {
		log.Fatal("CLUSTER_POD_CIDR is not set")
	}
	if *clusterSvcCidr == "" {
		log.Fatal("CLUSTER_SVC_CIDR is not set")
	}

	//====/ Transplaneur \==============================================

	transplaneurGatewayConfig := TransplaneurGatewayConfig{
		GatewayId:      *gatewayId,
		WgDeviceName:   *wgInterfaceName,
		ApiEndpoint:    *apiEndpoint,
		BearerToken:    *bearerToken,
		ClusterPodCidr: *clusterPodCidr,
		ClusterSvcCidr: *clusterSvcCidr,
	}

	transplaneurGateway, err := NewTransplaneurGateway(transplaneurGatewayConfig)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting %s", transplaneurGateway)
	// Initialize wireguard, etc.
	err = transplaneurGateway.Initiate()
	if err != nil {
		log.Fatal(err)
	}

	//====/ Metrics \===================================================

	initMetrics()

	go func() {
		for {
			updateWireGuardMetrics(transplaneurGateway)
			time.Sleep(30 * time.Second)
		}
	}()

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

		transplaneurGateway.Shutdown()

		// Exit the program
		os.Exit(0)
	}()

	//====/ HTTP API \======================================================

	// Create API server
	api := mux.NewRouter()

	// // Endpoint to expose metrics
	api.Handle("/metrics", promhttp.Handler()).Methods("GET")

	// Endpoint to expose health
	api.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {

		// exec command to check if wg is up
		cmd := exec.Command("ping", "-c", "1", "-W", "1", "-w", "1", "-q", transplaneurGateway.gatewayIp)
		err := cmd.Run()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Can't ping gateway "+transplaneurGateway.gatewayIp)
			return
		}

		// Expose health
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}).Methods("GET")

	// // Start API server
	log.Printf("Starting server on port %s...\n", *httpPort)
	log.Fatal(http.ListenAndServe(":"+*httpPort, api))

}
