package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"nhooyr.io/websocket"
)

type WSMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type ScanRequest struct {
	IPRange string `json:"ip_range"`
	Ports   []int  `json:"ports"`
}

func (a *Agent) startWebSocketServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", a.handleWebSocket)
	addr := fmt.Sprintf(":%d", a.config.ListenPort)
	log.Printf("WebSocket server listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func (a *Agent) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		log.Printf("WebSocket accept error: %v", err)
		return
	}
	defer conn.Close(websocket.StatusInternalError, "connection closed")

	for {
		_, msg, err := conn.Read(r.Context())
		if err != nil {
			log.Printf("WebSocket read error: %v", err)
			return
		}

		var wsMsg WSMessage
		if err := json.Unmarshal(msg, &wsMsg); err != nil {
			log.Printf("WebSocket unmarshal error: %v", err)
			continue
		}

		switch wsMsg.Type {
		case "scan":
			var req ScanRequest
			if err := json.Unmarshal(wsMsg.Payload, &req); err != nil {
				log.Printf("Scan request unmarshal error: %v", err)
				continue
			}
			a.handleScanRequest(r.Context(), conn, &req)
		case "ping":
			conn.Write(r.Context(), websocket.MessageText, []byte(`{"type":"pong"}`))
		}
	}
}

func (a *Agent) handleScanRequest(ctx context.Context, conn *websocket.Conn, req *ScanRequest) {
	// Placeholder: respond with empty scan results
	// Full implementation would:
	// 1. Parse IPRange (e.g. "192.168.1.0/24")
	// 2. Generate target IP list
	// 3. Scan each host using a.ScanHost()
	// 4. Stream results back via WebSocket

	// Send response directly without WSMessage wrapper to avoid double encoding
	respBytes, err := json.Marshal(map[string]interface{}{
		"type":    "scan_result",
		"devices": []interface{}{},
	})
	if err != nil {
		log.Printf("Failed to marshal scan response: %v", err)
		return
	}
	if err := conn.Write(ctx, websocket.MessageText, respBytes); err != nil {
		log.Printf("Failed to write scan response: %v", err)
	}
}