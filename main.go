package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"modules"

	"github.com/gorilla/websocket"
)

type Client struct {
	ID        string  `json:"client_id"` // Capitalized for JSON unmarshalling
	Latitude  float32 `json:"latitude"`
	Longitude float32 `json:"longitude"`
}

var (
	clients     = make(map[string]Client)
	connections = make(map[string]*websocket.Conn)
	mu          sync.Mutex

	database *sql.DB = modules.SetupDatabase()
)

func main() {
	// Serve static files (like login.html) from the "./static" directory
	fileServer := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static", fileServer))

	// When the root path "/" is visited, redirect to "/login.html"
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/login.html", http.StatusFound)
	})
	http.HandleFunc("/login", loginHandler)

	http.HandleFunc("/register_", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/register.html", http.StatusFound)
	})
	http.HandleFunc("/register", registerHandler)

	http.HandleFunc("/main", mainHandler)
	http.HandleFunc("/ws", handleWebSocket)

	go broadcastClientData()

	fmt.Println("Server is running at https://localhost:8080")
	log.Fatal(http.ListenAndServeTLS(":8080", "server.crt", "server.key", nil))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Login request")

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		return
	}

	username := r.FormValue("name")
	password := r.FormValue("address")

	if err := database.LoginUser(database, username, password); err != nil {
		return
	}

	http.Redirect(w, r, "/static/index.html", http.StatusFound)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		return
	}
	fmt.Fprintf(w, "POST request successful\n")

	username := r.FormValue("name")
	password := r.FormValue("address")

	if err := modules.RegisterUser(database, username, password); err != nil {
		return
	}

	http.Redirect(w, r, "/static/index.html", http.StatusFound)

}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Main request")
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("Error upgrading to WebSocket:", err)
		return
	}
	defer conn.Close()

	clientID := conn.RemoteAddr().String()

	mu.Lock()
	connections[clientID] = conn // You could also use `client.ID` instead of the remote address if needed
	mu.Unlock()

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {

			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				fmt.Printf("Client %s disconnect\n", clientID)

				mu.Lock()

				delete(clients, clientID)
				delete(connections, clientID)
				mu.Unlock()

				return
			}

			fmt.Println("Error reading message:", err)
			break
		}

		var client Client
		if err := json.Unmarshal(msg, &client); err != nil {
			fmt.Println("Error parsing JSON:", err)
			continue
		}

		mu.Lock()
		clients[clientID] = client // Use capitalized field name
		mu.Unlock()
	}
}

func broadcastClientData() {
	for {
		time.Sleep(1 * time.Second)

		mu.Lock()
		clientData := make([]Client, 0, len(clients))
		for _, client := range clients {
			clientData = append(clientData, client)
		}
		mu.Unlock()

		fmt.Println("Broadcasting client data:", clientData)

		// Send the current list of clients to all connected WebSockets
		message, err := json.Marshal(clientData)
		if err != nil {
			fmt.Println("Error marshalling client data:", err)
			continue
		}

		// Send message to each connection
		mu.Lock()
		for clientID, conn := range connections {
			if conn != nil && conn.PongHandler() != nil {
				err := conn.WriteMessage(websocket.TextMessage, message)
				if err != nil {
					fmt.Println("Error sending message:", err)
					// Connection might have been closed, so clean up
					delete(clients, clientID)
					delete(connections, clientID)
				}
			} else {
				// Connection closed, remove it from the list
				delete(clients, clientID)
				delete(connections, clientID)
			}
		}
		mu.Unlock()
	}
}
