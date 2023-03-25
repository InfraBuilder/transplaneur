package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"sync"
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

func NextIP(ip net.IP) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += 1
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)

	return net.IPv4(v0, v1, v2, v3)
}
