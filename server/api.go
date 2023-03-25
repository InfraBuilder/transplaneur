package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
)

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

func httpPostUnregister(ts *TransplaneurServer, w http.ResponseWriter, r *http.Request) {
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

	err = ts.UnregisterClient(req.PublicKey)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// =====/ AUTHENTICATION \================================================================================================

func checkBearer(w http.ResponseWriter, r *http.Request, bearerToken string) error {
	token := r.Header.Get("Authorization")
	if token != "Bearer "+bearerToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return fmt.Errorf("unauthorized")
	}
	return nil
}

// =====/ METRICS \=====================================================================================================

var (
	trafficEgress = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "wireguard_traffic_egress_bytes_total",
		Help: "Total number of egress bytes by the WireGuard interface",
	}, []string{"interface", "public_key", "client_ip"})

	trafficIngress = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "wireguard_traffic_ingress_bytes_total",
		Help: "Total number of ingress bytes by the WireGuard interface",
	}, []string{"interface", "public_key", "client_ip"})
)

func initMetrics() {
	prometheus.MustRegister(trafficEgress, trafficIngress)
}

var previousTraffic = make(map[string]struct {
	EgressBytes  int64
	IngressBytes int64
})

func removeWireguardPeerFromMetrics(ts *TransplaneurServer, publicKey string) {
	clientIP := ts.ipam.allocatedIPs[publicKey]
	trafficEgress.DeleteLabelValues("wg0", publicKey, clientIP)
	trafficIngress.DeleteLabelValues("wg0", publicKey, clientIP)
}

func updateWireGuardMetrics(ts *TransplaneurServer) {

	device, err := ts.wgClient.Device(ts.wgDeviceName)
	if err != nil {
		log.Printf("Failed to get WireGuard device: %v", err)
		return
	}

	for _, peer := range device.Peers {
		publicKey := peer.PublicKey.String()
		clientIP := ts.ipam.allocatedIPs[publicKey]
		egressBytes := peer.ReceiveBytes
		ingressBytes := peer.TransmitBytes

		egressBytesDelta := egressBytes
		ingressBytesDelta := ingressBytes

		// Get the previous values of egressBytes and ingressBytes for this peer
		if prev, ok := previousTraffic[publicKey]; ok {
			// Calculate the difference and update Prometheus metrics
			egressBytesDelta -= prev.EgressBytes
			ingressBytesDelta -= prev.IngressBytes

			if egressBytesDelta < 0 || ingressBytesDelta < 0 {
				log.Printf("WARNING: negative traffic delta for peer %s", publicKey)
				egressBytesDelta = 0
				ingressBytesDelta = 0
			}
		}

		// Update the previous values of egressBytes and ingressBytes for this peer
		previousTraffic[publicKey] = struct {
			EgressBytes  int64
			IngressBytes int64
		}{
			EgressBytes:  egressBytes,
			IngressBytes: ingressBytes,
		}

		// Update Prometheus metrics (assuming you have trafficEgress and trafficIngress GaugeVec)
		trafficEgress.WithLabelValues(ts.wgDeviceName, publicKey, clientIP).Add(float64(egressBytesDelta))
		trafficIngress.WithLabelValues(ts.wgDeviceName, publicKey, clientIP).Add(float64(ingressBytesDelta))
	}
}
