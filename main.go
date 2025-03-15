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
	"golang.org/x/crypto/bcrypt"
)

type Client struct {
	ID         string  `json:"id"`
	Username   string  `json:"username"`
	Latitude   float32 `json:"latitude"`
	Longitude  float32 `json:"longitude"`
	COLOR      string  `json:"color"`
	LastOnline string  `json:"lastonline"`
}

type LoginData struct {
	Username string `json:"username"`
	Password string `json:"password"`
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

func setSession(w http.ResponseWriter, id string) string {
	cookieValue := id + "-" + strconv.Itoa(rand.Intn(10000))
	sessions[cookieValue] = id

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    cookieValue,
		HttpOnly: true,
		Path:     "/",
	})

	return cookieValue
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Login request")

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var loginData LoginData
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&loginData); err != nil {
		http.Error(w, fmt.Sprintf("JSON decode error: %v", err), http.StatusBadRequest)
		return
	}

	unique_id, err := LoginUser(database, loginData.Username, loginData.Password)
	if err != nil {
		fmt.Println("Login failed:", err)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	cookie_id := setSession(w, unique_id)

	clients[cookie_id] = Client{
		ID:       unique_id,
		Username: loginData.Username,
		COLOR:    hexcolor.Format(uint8(rand.Intn(255)), uint8(rand.Intn(255)), uint8(rand.Intn(255))),
	}

	http.Redirect(w, r, "/main", http.StatusFound)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var registerData LoginData
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&registerData); err != nil {
		http.Error(w, fmt.Sprintf("JSON decode error: %v", err), http.StatusBadRequest)
		return
	}

	unique_id, err := RegisterUser(registerData.Username, registerData.Password)

	if err != nil {
		fmt.Println("Registration failed:", err)
		http.Redirect(w, r, "/", http.StatusFound)
		return // STOP execution
	}

	cookieValue := setSession(w, unique_id)

	clients[cookieValue] = Client{
		ID:       unique_id,
		Username: registerData.Username,
		COLOR:    hexcolor.Format(uint8(rand.Intn(255)), uint8(rand.Intn(255)), uint8(rand.Intn(255))),
	}

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
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	id, validSession := sessions[cookie.Value]
	if !validSession {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	htmlData, err := os.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "Error loading page", http.StatusInternalServerError)
		return
	}

	fmt.Println("Main request")

	customHTML := fmt.Sprintf(
		`<script>var username = "%s"; var id = "%s";</script>%s`,
		clients[cookie.Value].Username, id, string(htmlData))

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(customHTML))
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func processClientLocation(cookieValue string, client Client) {
	mu.Lock()
	existing, exists := clients[cookieValue]
	if exists {
		// Update only the fields that change (latitude, longitude, and last online if needed)
		existing.Latitude = client.Latitude
		existing.Longitude = client.Longitude
		existing.LastOnline = client.LastOnline

		clients[cookieValue] = existing
	}
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
		UpdateLastOnline(client, cookie.Value)
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

		offlineUsers, err := fetchOfflineUsersDB()
		if err != nil {
			fmt.Println("Error fetching offline users: ", err)
		}

		mu.Lock()
		clientData := make([]Client, 0, len(clients)+len(offlineUsers))

		// Prioritize online users
		for _, client := range clients {
			fmt.Println(client)
			clientData = append(clientData, client)
		}

		// Append offline users who are not in the online list
		for _, offlineUser := range offlineUsers {
			fmt.Println(offlineUser)
			if _, exists := clients[offlineUser.ID]; !exists {
				clientData = append(clientData, offlineUser)
			}
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
		for clientCookie, conn := range connections {
			go func(id string, c *websocket.Conn) {

				if c != nil {
					err := c.WriteMessage(websocket.TextMessage, message)
					if err != nil {
						fmt.Println("Error sending message:", err)
						// Connection might have been closed, so clean up
						delete(clients, clientCookie)
						delete(connections, clientCookie)
						fmt.Println("Removed Client ", clientCookie)
					}
				}
			}(clientCookie, conn)
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
		id TEXT NOT NULL PRIMARY KEY UNIQUE,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		last_online TEXT NOT NULL
	);
	`
	_, err = db.Exec(query)
	if err != nil {
		log.Fatal(err)
	}

	return db
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func RegisterUser(username, password string) (string, error) {
	unique_id := strconv.Itoa(rand.Intn(1000000000))

	return unique_id, RegisterUserDB(database, username, password, unique_id)
}

func RegisterUserDB(db *sql.DB, username, password, id string) error {

	// Check if the username already exists
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("username %s already exists", username)
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		return err
	}

	// Insert new user into the database
	_, err = db.Exec("INSERT INTO users (id, username, password, last_online) VALUES (?, ?, ?, ?)", id, username, hashedPassword, LastOnline())
	return err
}

func LoginUser(db *sql.DB, username, password string) (string, error) {
	var storedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return "_", err
		}
		return "_", err
	}
	if !checkPasswordHash(password, storedPassword) {
		return "_", err
	}
	// Update last_online timestamp after successful login
	db.Exec("UPDATE users SET last_online = ? WHERE username = ?", LastOnline(), username)
	var userID string
	err = db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
	if err != nil {
		return "_", err
	}
	return userID, nil
}

func LastOnline() string {
	return time.Now().Format("2006-01-02 15:04")
}

func UpdateLastOnline(client Client, cookieValue string) {
	now := LastOnline()

	client.LastOnline = now

	clients[cookieValue] = client

	UpdateLastOnlineDB(database, client.ID, now)
}

// UpdateLastOnline updates the last online timestamp for a given user in the database.
func UpdateLastOnlineDB(db *sql.DB, id string, time string) {
	now := LastOnline() // e.g. "2006-01-02 15:04"
	_, err := db.Exec("UPDATE users SET last_online = ? WHERE id = ?", now, id)
	if err != nil {
		fmt.Println("Error updating last online for", id, ":", err)
	}
}

func fetchOfflineUsersDB() ([]Client, error) {
	var offlineUsers []Client
	rows, err := database.Query("SELECT id, username, last_online FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var user Client
		if err := rows.Scan(&user.ID, &user.Username, &user.LastOnline); err != nil {
			return nil, err
		}

		// Filter out users who are online by checking if any client has the same username.
		isOnline := false
		mu.Lock()
		for _, onlineClient := range clients {
			if onlineClient.ID == user.ID {
				isOnline = true
				break
			}
		}
		mu.Unlock()

		if !isOnline {
			offlineUsers = append(offlineUsers, user)
		}
	}
	return offlineUsers, nil
}
