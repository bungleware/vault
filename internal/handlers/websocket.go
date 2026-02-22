package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"bungleware/vault/internal/middleware"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// TODO: adjust, allow all origins in development
		return true
	},
}

type WSMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

type TranscodingUpdate struct {
	TrackPublicID string `json:"track_public_id"`
	VersionID     int64  `json:"version_id"`
	Status        string `json:"status"` // pending, processing, completed, failed
}

type WSHub struct {
	connections map[int64]map[*websocket.Conn]bool
	mu          sync.RWMutex
}

func NewWSHub() *WSHub {
	return &WSHub{
		connections: make(map[int64]map[*websocket.Conn]bool),
	}
}

func (h *WSHub) Register(userID int64, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.connections[userID] == nil {
		h.connections[userID] = make(map[*websocket.Conn]bool)
	}
	h.connections[userID][conn] = true
	log.Printf("[WebSocket] User %d connected (total connections: %d)", userID, len(h.connections[userID]))
}

func (h *WSHub) Unregister(userID int64, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if conns, ok := h.connections[userID]; ok {
		delete(conns, conn)
		if len(conns) == 0 {
			delete(h.connections, userID)
		}
		log.Printf("[WebSocket] User %d disconnected", userID)
	}
}

func (h *WSHub) SendToUser(userID int64, msg WSMessage) {
	h.mu.RLock()
	conns := h.connections[userID]
	h.mu.RUnlock()

	if conns == nil {
		log.Printf("[WebSocket] No connections for user %d, message not sent", userID)
		return
	}

	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("[WebSocket] Failed to marshal message: %v", err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	log.Printf("[WebSocket] Sending message to user %d (%d connections): %s", userID, len(conns), string(data))

	for conn := range conns {
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Printf("[WebSocket] Failed to send message: %v", err)
			// Don't remove here - let the read loop handle disconnection
		}
	}
}

func (h *WSHub) BroadcastTranscodingUpdate(userID int64, update TranscodingUpdate) {
	h.SendToUser(userID, WSMessage{
		Type:    "transcoding_update",
		Payload: update,
	})
}

func (h *WSHub) NotifyTranscodingUpdate(userID int64, trackPublicID string, versionID int64, status string) {
	h.BroadcastTranscodingUpdate(userID, TranscodingUpdate{
		TrackPublicID: trackPublicID,
		VersionID:     versionID,
		Status:        status,
	})
}

type WebSocketHandler struct {
	hub *WSHub
}

func NewWebSocketHandler(hub *WSHub) *WebSocketHandler {
	return &WebSocketHandler{hub: hub}
}

func (h *WebSocketHandler) HandleConnection(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WebSocket] Failed to upgrade connection: %v", err)
		return
	}

	h.hub.Register(int64(userID), conn)

	go h.handleConnection(int64(userID), conn)
}

func (h *WebSocketHandler) handleConnection(userID int64, conn *websocket.Conn) {
	defer func() {
		h.hub.Unregister(userID, conn)
		conn.Close()
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[WebSocket] Unexpected close error: %v", err)
			}
			break
		}
	}
}

type CollaborationHub struct {
	rooms map[string]*CollaborationRoom
	mu    sync.RWMutex
}

func NewCollaborationHub() *CollaborationHub {
	return &CollaborationHub{
		rooms: make(map[string]*CollaborationRoom),
	}
}

type CollaborationRoom struct {
	ID         string
	Clients    map[*CollaborationClient]bool
	Broadcast  chan *CollaborationMessage
	Register   chan *CollaborationClient
	Unregister chan *CollaborationClient
	mu         sync.RWMutex
}

type CollaborationClient struct {
	ID              string
	UserID          int64
	Username        string
	UserInstanceURL string
	Room            *CollaborationRoom
	Conn            *websocket.Conn
	Send            chan *CollaborationMessage
}

type CollaborationMessage struct {
	Type      string                 `json:"type"`
	Data      map[string]interface{} `json:"data"`
	Timestamp string                 `json:"timestamp"`
	UserID    int64                  `json:"user_id"`
	Username  string                 `json:"username"`
	SessionID string                 `json:"session_id"`
}

func (h *CollaborationHub) GetOrCreateRoom(roomID string) *CollaborationRoom {
	h.mu.Lock()
	defer h.mu.Unlock()

	room, exists := h.rooms[roomID]
	if !exists {
		room = &CollaborationRoom{
			ID:         roomID,
			Clients:    make(map[*CollaborationClient]bool),
			Broadcast:  make(chan *CollaborationMessage, 256),
			Register:   make(chan *CollaborationClient),
			Unregister: make(chan *CollaborationClient),
		}
		h.rooms[roomID] = room
		go room.run()
	}

	return room
}

func (r *CollaborationRoom) run() {
	for {
		select {
		case client := <-r.Register:
			r.mu.Lock()
			r.Clients[client] = true
			r.mu.Unlock()

			participants := []map[string]interface{}{}
			r.mu.RLock()
			for c := range r.Clients {
				if c.ID != client.ID {
					participants = append(participants, map[string]interface{}{
						"user_id":    c.UserID,
						"username":   c.Username,
						"session_id": c.ID,
					})
				}
			}
			r.mu.RUnlock()

			client.Send <- &CollaborationMessage{
				Type: "participants",
				Data: map[string]interface{}{
					"participants": participants,
				},
			}

		case client := <-r.Unregister:
			r.mu.Lock()
			if _, ok := r.Clients[client]; ok {
				delete(r.Clients, client)
				close(client.Send)
			}
			r.mu.Unlock()

		case message := <-r.Broadcast:
			r.mu.RLock()
			for client := range r.Clients {
				if client.ID != message.SessionID {
					select {
					case client.Send <- message:
					default:
						close(client.Send)
						delete(r.Clients, client)
					}
				}
			}
			r.mu.RUnlock()
		}
	}
}

func (h *CollaborationHub) BroadcastUpdate(roomID string, updateType string, data map[string]interface{}, userID int64, username string, sessionID string) {
	h.mu.RLock()
	room, exists := h.rooms[roomID]
	h.mu.RUnlock()

	if !exists {
		return
	}

	room.Broadcast <- &CollaborationMessage{
		Type:      updateType,
		Data:      data,
		Timestamp: "",
		UserID:    userID,
		Username:  username,
		SessionID: sessionID,
	}
}

type CollaborationWebSocketHandler struct {
	hub *CollaborationHub
}

func NewCollaborationWebSocketHandler(hub *CollaborationHub) *CollaborationWebSocketHandler {
	return &CollaborationWebSocketHandler{hub: hub}
}

func (h *CollaborationWebSocketHandler) HandleCollaboration(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	resourceType := r.URL.Query().Get("type")
	resourceID := r.URL.Query().Get("id")
	username := r.URL.Query().Get("username")

	if resourceType == "" || resourceID == "" {
		http.Error(w, "missing resource type or ID", http.StatusBadRequest)
		return
	}

	roomID := resourceType + ":" + resourceID

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[Collaboration] Failed to upgrade connection: %v", err)
		return
	}

	client := &CollaborationClient{
		ID:       generateSessionID(),
		UserID:   int64(userID),
		Username: username,
		Room:     h.hub.GetOrCreateRoom(roomID),
		Conn:     conn,
		Send:     make(chan *CollaborationMessage, 256),
	}

	client.Room.Register <- client

	go client.writePump()
	go client.readPump()
}

func (c *CollaborationClient) readPump() {
	defer func() {
		c.Room.Unregister <- c
		c.Conn.Close()
	}()

	for {
		var msg CollaborationMessage
		err := c.Conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[Collaboration] Unexpected close error: %v", err)
			}
			break
		}

		msg.UserID = c.UserID
		msg.Username = c.Username
		msg.SessionID = c.ID

		c.Room.Broadcast <- &msg
	}
}

func (c *CollaborationClient) writePump() {
	defer c.Conn.Close()

	for msg := range c.Send {
		err := c.Conn.WriteJSON(msg)
		if err != nil {
			log.Printf("[Collaboration] Failed to write message: %v", err)
			break
		}
	}
}

func generateSessionID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
