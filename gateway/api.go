package gateway

import (
	"log"

	"github.com/prometheus/client_golang/prometheus"
)

// =====/ METRICS \=====================================================================================================

var (
	trafficEgress = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "wireguard_traffic_egress_bytes_total",
		Help: "Total number of egress bytes by the WireGuard interface",
	}, []string{"interface", "public_key"})

	trafficIngress = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "wireguard_traffic_ingress_bytes_total",
		Help: "Total number of ingress bytes by the WireGuard interface",
	}, []string{"interface", "public_key"})
)

func initMetrics() {
	prometheus.MustRegister(trafficEgress, trafficIngress)
}

var previousTraffic = make(map[string]struct {
	EgressBytes  int64
	IngressBytes int64
})

func updateWireGuardMetrics(tg *TransplaneurGateway) {

	device, err := tg.wgClient.Device(tg.wgDeviceName)
	if err != nil {
		log.Printf("Failed to get WireGuard device: %v", err)
		return
	}

	peersStatsToRemove := make(map[string]bool)
	for publicKey := range previousTraffic {
		peersStatsToRemove[publicKey] = true
	}

	for _, peer := range device.Peers {
		publicKey := peer.PublicKey.String()

		// Remove the peer from the list of peers to remove (lol)
		delete(peersStatsToRemove, publicKey)

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
		trafficEgress.WithLabelValues(tg.wgDeviceName, publicKey).Add(float64(egressBytesDelta))
		trafficIngress.WithLabelValues(tg.wgDeviceName, publicKey).Add(float64(ingressBytesDelta))
	}

	// Remove the peers that are not in the WireGuard device anymore
	for publicKey := range peersStatsToRemove {
		delete(previousTraffic, publicKey)
	}
}
