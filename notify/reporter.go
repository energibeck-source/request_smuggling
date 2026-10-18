package notify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type TelegramNotifier struct {
	BotToken string
	ChatID   string
	Client   *http.Client
}

func NewTelegramNotifier(chatID string) *TelegramNotifier {

	getenv := os.Getenv("TELEGRAM_BOT_TOKEN_BASE64")
	var decode []byte

	if getenv != "" {
		var err error
		decode, err = base64.StdEncoding.DecodeString(getenv)
		if err != nil {
			log.Printf("Error decoding BOT_TOKEN: %v", err)
			decode = nil
		}
	}

	botToken := string(decode)

	return &TelegramNotifier{
		BotToken: botToken,
		ChatID:   chatID,
		Client:   &http.Client{Timeout: 5 * time.Second},
	}
}

func (t *TelegramNotifier) SendReport(text string) error {
	if t.BotToken == "" || t.ChatID == "" {
		return nil
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.BotToken)
	payload := map[string]interface{}{
		"chat_id":              t.ChatID,
		"text":                 text,
		"parse_mode":           "HTML",
		"disable_notification": true,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}

	resp, err := t.Client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("HTTP POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API error: %s", resp.Status)
	}
	return nil
}
