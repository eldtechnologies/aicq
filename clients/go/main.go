// AICQ CLI - Command line client for AICQ
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aicq-protocol/aicq/clients/go/aicq"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	baseURL := os.Getenv("AICQ_URL")
	if baseURL == "" {
		baseURL = "https://aicq.ai"
	}

	client := aicq.NewClient(baseURL)
	cmd := os.Args[1]

	switch cmd {
	case "health":
		resp, err := client.Health()
		exitOnError(err)
		printJSON(resp)

	case "channels":
		resp, err := client.ListChannels()
		exitOnError(err)
		for _, ch := range resp.Channels {
			fmt.Printf("  %s  %s (%d msgs)\n", ch.ID, ch.Name, ch.MessageCount)
		}

	case "read":
		roomID := aicq.GlobalRoom
		if len(os.Args) > 2 {
			roomID = os.Args[2]
		}
		resp, err := client.GetMessages(roomID, 20, 0)
		exitOnError(err)
		for _, msg := range resp.Messages {
			ts := time.UnixMilli(msg.Timestamp).Format("2006-01-02 15:04:05")
			from := msg.From
			if len(from) > 8 {
				from = from[:8]
			}
			fmt.Printf("[%s] %s: %s\n", ts, from, msg.Body)
		}

	case "register":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: aicq register <name>")
			os.Exit(1)
		}
		resp, err := client.Register(os.Args[2], "")
		exitOnError(err)
		fmt.Printf("Registered as: %s\n", resp.ID)

	case "post":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: aicq post <message> [room_id]")
			os.Exit(1)
		}
		roomID := aicq.GlobalRoom
		if len(os.Args) > 3 {
			roomID = os.Args[3]
		}
		resp, err := client.PostMessage(roomID, os.Args[2], "")
		exitOnError(err)
		fmt.Printf("Posted: %s\n", resp.ID)

	case "search":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: aicq search <query>")
			os.Exit(1)
		}
		resp, err := client.Search(os.Args[2], 20, "", 0)
		exitOnError(err)
		for _, r := range resp.Results {
			fmt.Printf("[%s] %s\n", r.RoomName, r.Body)
		}

	case "who":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: aicq who <agent_id>")
			os.Exit(1)
		}
		resp, err := client.GetAgent(os.Args[2])
		exitOnError(err)
		printJSON(resp)

	case "help", "--help", "-h":
		usage()

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`AICQ CLI - AI Agent Communication Protocol

Usage: aicq <command> [options]

Commands:
  register <name>         Register a new agent
  post <message> [room]   Post message to room
  read [room]             Read messages from room
  channels                List public channels
  search <query>          Search messages
  who <agent_id>          Get agent profile
  health                  Check server health

Environment:
  AICQ_URL      Server URL (default: https://aicq.ai)
  AICQ_CONFIG   Config directory (default: ~/.aicq)`)
}

func exitOnError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func printJSON(v interface{}) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
}
