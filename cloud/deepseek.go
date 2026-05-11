package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type DeepSeekRequest struct {
	Model    string              `json:"model"`
	Messages []map[string]string `json:"messages"`
	Stream   bool                `json:"stream"`
}

type DeepSeekResponse struct {
	ID      string `json:"id"`
	Choices []struct {
		Message map[string]string `json:"message"`
	} `json:"choices"`
}

type ReportRequest struct {
	ScanData map[string]interface{} `json:"scan_data"`
	Locale   string                 `json:"locale"` // "zh" or "en"
}

func CallDeepSeekChat(prompt string) (string, error) {
	cfg := LoadCloudConfig()

	body := DeepSeekRequest{
		Model: "deepseek-chat",
		Messages: []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	payload, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", cfg.DeepSeekURL+"/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.DeepSeekKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("DeepSeek API call failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("DeepSeek API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var dsResp DeepSeekResponse
	json.Unmarshal(bodyBytes, &dsResp)
	if len(dsResp.Choices) == 0 {
		return "", fmt.Errorf("no response from DeepSeek")
	}
	return dsResp.Choices[0].Message["content"], nil
}

func CallDeepSeekReasoner(prompt string) (string, error) {
	cfg := LoadCloudConfig()

	body := DeepSeekRequest{
		Model: "deepseek-reasoner",
		Messages: []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	payload, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", cfg.DeepSeekURL+"/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.DeepSeekKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("DeepSeek API call failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read DeepSeek response body: %w", err)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("DeepSeek API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var dsResp DeepSeekResponse
	if err := json.Unmarshal(bodyBytes, &dsResp); err != nil {
		return "", fmt.Errorf("failed to parse DeepSeek response: %w", err)
	}
	if len(dsResp.Choices) == 0 {
		return "", fmt.Errorf("no response from DeepSeek")
	}
	return dsResp.Choices[0].Message["content"], nil
}

func buildReportPrompt(scanData map[string]interface{}) string {
	return "请根据以下扫描结果生成安全报告。"
}