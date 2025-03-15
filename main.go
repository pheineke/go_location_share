package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"github.com/reiver/go-hexcolor"
)

type Client struct {
	ID        string  `json:"id"`
	Username  string  `json:"username"`
	Latitude  float32 `json:"latitude"`
	Longitude float32 `json:"longitude"`
	COLOR     string  `json:"color"`
}

type ClientLocationResponse struct {
	MSGTYPE string `json:"MSGTYPE"`
	CONTENT string `json:"CONTENT"`
}

var (
	clients     = make(map[string]Client)
	connections = make(map[string]*websocket.Conn)
	mu          sync.Mutex

	database *sql.DB = SetupDatabase()

	sessions = make(map[string]string)
)

const maxConnections = 20 // Set your limit here
var currentConnections int

func main() {
	// Serve static files (like login.html) from the "./static" directory
	fileServer := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static", fileServer))

	// When the root path "/" is visited, redirect to "/login.html"
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/login.html", http.StatusFound)
	})
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/logout", logoutHandler)

	http.HandleFunc("/register_", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/register.html", http.StatusFound)
	})

	http.HandleFunc("/main", mainHandler)
	http.HandleFunc("/ws", handleWebSocket)

	go broadcastClientData()

	fmt.Println("Server is running at https://localhost:8080")
	log.Fatal(http.ListenAndServeTLS(":8080", "server.crt", "server.key", nil))
}

func setSession(w http.ResponseWriter, username string) {
	sessionID := strconv.Itoa(rand.Intn(1000000000))
	sessions[sessionID] = username

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		HttpOnly: true,
		Path:     "/",
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Login request")

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		http.Redirect(w, r, "/", http.StatusFound)
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if err := LoginUser(database, username, password); err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
	}

	setSession(w, username)

	http.Redirect(w, r, "/main", http.StatusFound)
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

	username := r.FormValue("username")
	password := r.FormValue("password")

	if err := RegisterUser(database, username, password); err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
	}

	setSession(w, username)

	http.Redirect(w, r, "/main", http.StatusFound)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil && cookie.Value != "" {
		delete(sessions, cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		HttpOnly: true,
		Path:     "/",
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil || cookie.Value == "" || sessions[cookie.Value] == "" {
		http.Redirect(w, r, "/", http.StatusFound)
	}

	htmlData, err := os.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "Error loading page", http.StatusInternalServerError)
		return
	}

	fmt.Println("Main request")

	username := sessions[cookie.Value]
	customHTML := fmt.Sprintf(
		`<script>var username = "%s"; var id = "%s";</script>%s`,
		username, cookie.Value, string(htmlData))

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(customHTML))
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func processClientLocation(cookieValue string, client Client) {
	client.ID = cookieValue
	client.Username = sessions[cookieValue]
	client.COLOR = hexcolor.Format(uint8(rand.Intn(255)), uint8(rand.Intn(255)), uint8(rand.Intn(255)))

	mu.Lock()
	clients[cookieValue] = client
	mu.Unlock()
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	if currentConnections >= maxConnections {
		mu.Unlock()
		http.Error(w, "Too many connections", http.StatusTooManyRequests)
		return
	}
	currentConnections++
	mu.Unlock()

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("Error upgrading to WebSocket:", err)
		mu.Lock()
		currentConnections-- // Decrease on failure
		mu.Unlock()
		return
	}
	defer conn.Close()

	cookie, err := r.Cookie("session_id")
	if err != nil || cookie.Value == "" || sessions[cookie.Value] == "" {
		errMsg := "Unauthorized: no valid session"
		conn.WriteMessage(websocket.CloseMessage, []byte(errMsg))
		return
	}

	mu.Lock()
	connections[cookie.Value] = conn
	mu.Unlock()

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				fmt.Printf("Client %s disconnected\n", cookie.Value)
			} else {
				fmt.Println("Error reading message:", err)
			}
			break
		}

		var client Client
		if err := json.Unmarshal(msg, &client); err != nil {
			fmt.Println("Error parsing JSON:", err)
			continue
		}

		processClientLocation(cookie.Value, client)
	}

	// Cleanup after disconnection
	mu.Lock()
	delete(clients, cookie.Value)
	delete(connections, cookie.Value)
	currentConnections-- // Decrease count when a client disconnects
	mu.Unlock()
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
			go func(id string, c *websocket.Conn) {

				if c != nil {
					err := c.WriteMessage(websocket.TextMessage, message)
					if err != nil {
						fmt.Println("Error sending message:", err)
						// Connection might have been closed, so clean up
						delete(clients, clientID)
						delete(connections, clientID)
						fmt.Println("Removed Client ", clientID)
						mu.Unlock()
					}
				}
			}(clientID, conn)
		}
		mu.Unlock()
	}
}

// // DATABASE
func SetupDatabase() *sql.DB {
	// Open or create the database file
	db, err := sql.Open("sqlite3", "file:users.db?_busy_timeout=5000&cache=shared")
	if err != nil {
		log.Fatal(err)
	}

	// Create the table if it doesn't exist
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	);
	`
	_, err = db.Exec(query)
	if err != nil {
		log.Fatal(err)
	}

	return db
}

func RegisterUser(db *sql.DB, username, password string) error {
	// Check if the username already exists
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("username %s already exists", username)
	}

	// Insert new user into the database
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, password)
	return err
}

func LoginUser(db *sql.DB, username, password string) error {
	var storedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("username %s does not exist", username)
		}
		return err
	}
	if storedPassword != password {
		return fmt.Errorf("invalid password for user %s", username)
	}
	return nil
}
