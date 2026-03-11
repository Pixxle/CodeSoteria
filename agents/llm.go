package agents

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

// LLMClient defines the interface for calling an LLM to process agent prompts.
type LLMClient interface {
	// Complete sends a prompt to the LLM and returns the response text.
	Complete(systemPrompt, userPrompt string) (string, error)
}

// AnthropicClient calls the Anthropic Messages API.
type AnthropicClient struct {
	APIKey string
	Model  string
	client *http.Client
}

// NewAnthropicClient creates a client for the Anthropic API.
// API key is read from ANTHROPIC_API_KEY env var if not provided.
func NewAnthropicClient(apiKey, model string) *AnthropicClient {
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}
	return &AnthropicClient{
		APIKey: apiKey,
		Model:  model,
		client: &http.Client{},
	}
}

func (c *AnthropicClient) Complete(systemPrompt, userPrompt string) (string, error) {
	if c.APIKey == "" {
		return "", fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	body := map[string]any{
		"model":      c.Model,
		"max_tokens": 8192,
		"system":     systemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": userPrompt},
		},
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(jsonBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic API: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("anthropic API %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if len(result.Content) == 0 {
		return "", fmt.Errorf("empty response from Anthropic API")
	}

	return result.Content[0].Text, nil
}

// NoOpLLMClient is a placeholder that returns empty findings (for tool-only mode).
type NoOpLLMClient struct{}

func (c *NoOpLLMClient) Complete(systemPrompt, userPrompt string) (string, error) {
	return "[]", nil
}
