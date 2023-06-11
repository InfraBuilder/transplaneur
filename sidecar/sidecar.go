package sidecar

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
)

const (
	sidecarCommunicationDirectory = "/var/run/transplaneur"
	sidecarLibDirectory           = "/var/lib/transplaneur"
	waitGatewayPeriod             = 5 * time.Second
	watchGatewayPeriod            = 1 * time.Second
)

type TransplaneurSidecar struct {
	gatewayId        string
	defaultInterface string
	originalGateway  string
	currentGatewayIp string
}

func NewTransplaneurSidecar(gatewayId string) (*TransplaneurSidecar, error) {

	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)

	if err != nil {
		return nil, fmt.Errorf("could not list routes: %v", err)
	}

	var defaultRoute *netlink.Route
	for _, route := range routes {
		if route.Dst == nil {
			defaultRoute = &route
			break
		}
	}

	if defaultRoute == nil {
		return nil, fmt.Errorf("could not find default route")
	}

	link, err := netlink.LinkByIndex(defaultRoute.LinkIndex)
	if err != nil {
		return nil, fmt.Errorf("could not get default interface: %v", err)
	}

	return &TransplaneurSidecar{
		gatewayId:        gatewayId,
		defaultInterface: link.Attrs().Name,
		originalGateway:  defaultRoute.Gw.String(),
		currentGatewayIp: "",
	}, nil
}

func (ts *TransplaneurSidecar) String() string {
	return fmt.Sprintf("TransplaneurSidecar(gatewayId=%s)", ts.gatewayId)
}

func (ts *TransplaneurSidecar) Initiate() error {
	log.Printf("Initializing %s", ts)

	// create files on communication channel
	err := os.MkdirAll(sidecarCommunicationDirectory+"/"+ts.gatewayId, 0755)
	if err != nil {
		return fmt.Errorf("failed to create transplaneur directory: %v", err)
	}

	return nil
}

func ensureRouteIsCorrect(dst string, gw string, device string, customMtu string) error {

	cmd := exec.Command("ip", "route", "show", dst)
	cmdOutputBytes, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("Error while running ip route command: %v", err)
	}

	expectedRoute := ""
	if customMtu != "" {
		expectedRoute = fmt.Sprintf("%s via %s dev %s mtu %s", dst, gw, device, customMtu)
	} else {
		expectedRoute = fmt.Sprintf("%s via %s dev %s", dst, gw, device)
	}
	cmdOutput := string(cmdOutputBytes)

	if err != nil {
		log.Printf("Error while getting route output: %v", err)
	}

	if string(cmdOutput) != expectedRoute {
		if cmdOutput != "" {
			cmd = exec.Command("ip", "route", "del", dst)
			_, err = cmd.Output()
			if err != nil {
				log.Printf("Error while deleting route: %v", err)
			}
		}
		if customMtu != "" {
			cmd = exec.Command("ip", "route", "add", dst, "via", gw, "dev", device, "mtu", customMtu)
		} else {
			cmd = exec.Command("ip", "route", "add", dst, "via", gw, "dev", device)
		}
		_, err = cmd.Output()
		if err != nil {
			log.Printf("Error while adding route: %v", err)
		}
		log.Printf("Route for %s is now %s", dst, expectedRoute)
	} else {
		log.Printf("Route for %s is correct", dst)
	}
	return nil
}

func (ts *TransplaneurSidecar) ChangeGateway(gatewayIp string, gatewayMtu string, clusterPodCidr string, clusterSvcCidr string) error {

	log.Println(fmt.Sprintf("Changing gateway from %s to %s", ts.currentGatewayIp, gatewayIp))

	// Set route to Pod CIDR
	err := ensureRouteIsCorrect(clusterPodCidr, ts.originalGateway, ts.defaultInterface, "")
	if err != nil {
		return fmt.Errorf("could not set route to clusterPodCidr: %v", err)
	}

	// Set route to Service CIDR
	err = ensureRouteIsCorrect(clusterSvcCidr, ts.originalGateway, ts.defaultInterface, "")
	if err != nil {
		return fmt.Errorf("could not set route to clusterSvcCidr: %v", err)
	}

	// Set default route to Gateway IP
	err = ensureRouteIsCorrect("default", gatewayIp, ts.defaultInterface, gatewayMtu)
	if err != nil {
		return fmt.Errorf("could not set default route to gatewayIp: %v", err)
	}

	// Flush ARP cache
	exec.Command("ip", "n", "flush", "all").Run()

	ts.currentGatewayIp = gatewayIp

	return nil
}

func (ts *TransplaneurSidecar) CheckGatewayChange() error {
	// Wait for gateway file to be exist
	for {
		_, err := os.Stat(fmt.Sprintf("%s/%s/local-gateway", sidecarCommunicationDirectory, ts.gatewayId))
		if err == nil {
			break
		}
		log.Printf("Waiting for gateway to be ready... (will retry in %s)", waitGatewayPeriod)
		time.Sleep(waitGatewayPeriod)
	}

	// Read gatewayIp from file
	gatewayIpBytes, err := os.ReadFile(fmt.Sprintf("%s/%s/local-gateway", sidecarCommunicationDirectory, ts.gatewayId))
	if err != nil {
		return fmt.Errorf("could not read gatewayIp: %v", err)
	}
	gatewayIp := string(gatewayIpBytes)

	if gatewayIp != ts.currentGatewayIp {

		// Read clusterPodCidr from file
		clusterPodCidrBytes, err := os.ReadFile(fmt.Sprintf("%s/%s/cluster-pod-cidr", sidecarCommunicationDirectory, ts.gatewayId))
		if err != nil {
			return fmt.Errorf("could not read clusterPodCidr: %v", err)
		}
		clusterPodCidr := string(clusterPodCidrBytes)

		// Read clusterSvcCidr from file
		clusterSvcCidrBytes, err := os.ReadFile(fmt.Sprintf("%s/%s/cluster-svc-cidr", sidecarCommunicationDirectory, ts.gatewayId))
		if err != nil {
			return fmt.Errorf("could not read clusterSvcCidr: %v", err)
		}
		clusterSvcCidr := string(clusterSvcCidrBytes)

		// Read optionnal mtu file to set custom MTU
		gatewayMtu := ""
		gatewayMtuBytes, err := os.ReadFile(fmt.Sprintf("%s/%s/gateway-mtu", sidecarCommunicationDirectory, ts.gatewayId))
		if err == nil {
			gatewayMtu = string(gatewayMtuBytes)
			log.Printf("Using custom MTU: %s", gatewayMtu)
		} else {
			log.Printf(fmt.Sprintf("Cannot read %s/%s/gateway-mtu, Using default MTU", sidecarCommunicationDirectory, ts.gatewayId))
		}

		err = ts.ChangeGateway(gatewayIp, gatewayMtu, clusterPodCidr, clusterSvcCidr)
		if err != nil {
			return fmt.Errorf("could not change gateway: %v", err)
		}
	}

	return nil
}

func (ts *TransplaneurSidecar) Shutdown() error {
	log.Printf("Shutting down %s", ts)
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

	fmt.Println("\nOptional flags/environment variables:")
	subcommandFlagSet.VisitAll(func(f *flag.Flag) {
		if f.Name != "h" && f.Name != "help" {
			fmt.Printf("\t-%s=%s\n\t\t%s\n", f.Name, f.DefValue, f.Usage)
		}
	})

	fmt.Println("\nHelp flags:")
	fmt.Println("  -h, -help: Print help")
}

func Start() {

	//====/ Configuration \=============================================

	subcommandFlagSet := flag.NewFlagSet("sidecar", flag.ExitOnError)

	// Mandatory flags/environment variables

	// Optional flags/environment variables
	httpPort := subcommandFlagSet.String("http-port", getenvOrDefault("HTTP_LISTEN_PORT", "8080"), "HTTP listen port (HTTP_LISTEN_PORT)")
	gatewayId := subcommandFlagSet.String("gateway-id", getenvOrDefault("GATEWAY_ID", "default"), "Identifier for this gateway (GATEWAY_ID)")

	helpFlag := subcommandFlagSet.Bool("h", false, "Print help")
	helpLongFlag := subcommandFlagSet.Bool("help", false, "Print help")

	subcommandFlagSet.Parse(os.Args[2:])

	if *helpFlag || *helpLongFlag {
		printUsage(subcommandFlagSet)
		return
	}

	//====/ Transplaneur \==============================================

	transplaneurSidecar, err := NewTransplaneurSidecar(*gatewayId)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting %s", transplaneurSidecar)
	// Initialize wireguard, etc.
	err = transplaneurSidecar.Initiate()
	if err != nil {
		log.Fatal(err)
	}

	// Start the main loop

	// Waiting for gateway to be ready
	go func() {
		for {
			err := transplaneurSidecar.CheckGatewayChange()
			if err != nil {
				log.Printf("Error while checking gateway change: %v", err)
			}
			time.Sleep(watchGatewayPeriod)
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

		transplaneurSidecar.Shutdown()

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
		// Expose health
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}).Methods("GET")

	// // Start API server
	log.Printf("Starting server on port %s...\n", *httpPort)
	log.Fatal(http.ListenAndServe(":"+*httpPort, api))

}
