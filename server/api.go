package server

import (
	"encoding/json"
	"net/http"
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
