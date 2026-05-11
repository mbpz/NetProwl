package main

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := LoadCloudConfig()

	r := gin.Default()

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// WebSocket relay endpoint
	r.GET("/ws/relay", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "TODO"})
	})

	// Report generation API
	r.POST("/api/report", func(c *gin.Context) {
		var req ReportRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "invalid request"})
			return
		}

		prompt := buildReportPrompt(req.ScanData)
		result, err := CallDeepSeekReasoner(prompt)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		c.JSON(200, gin.H{"report": result})
	})

	log.Printf("Cloud server starting on :%d", cfg.ListenPort)
	if err := r.Run(fmt.Sprintf(":%d", cfg.ListenPort)); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}