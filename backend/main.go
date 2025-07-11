package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3" // SQLite driver
	"golang.org/x/crypto/bcrypt"
)

// --- Structs ---
type Document struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	FilePath string `json:"-"`
	UserID   string `json:"userId"`
	Category string `json:"category,omitempty"` // Added category
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"` // Password hash
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	UserID string `json:"userId"`
	jwt.RegisteredClaims
}

// --- Global Variables ---
var (
	db         *sql.DB
	uploadsDir = "./uploads" // Should be relative to where the binary runs or absolute
	dbPath     = "./data/home_docs.db" // Path for the SQLite DB file
	jwtKey     = []byte("your_secret_key_please_change_in_prod")
)

// --- Database Initialization ---
func initDB() {
	var err error
	// Ensure the data directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		log.Fatalf("Error creating data directory: %v", err)
	}

	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	createUserTable := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL
	);`
	_, err = db.Exec(createUserTable)
	if err != nil {
		log.Fatalf("Error creating users table: %v", err)
	}

	createDocumentTable := `
	CREATE TABLE IF NOT EXISTS documents (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		file_path TEXT NOT NULL,
		user_id TEXT NOT NULL,
		category TEXT DEFAULT '',     -- Added category, default to empty string
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	);`
	_, err = db.Exec(createDocumentTable)
	if err != nil {
		log.Fatalf("Error creating documents table: %v", err)
	}

	// Index for user-specific document listing and category filtering
	createDocUserCategoryIndex := `CREATE INDEX IF NOT EXISTS idx_doc_user_category ON documents (user_id, category, created_at);`
	_, err = db.Exec(createDocUserCategoryIndex)
	if err != nil {
		// Non-fatal for index creation, but log it
		log.Printf("Warning: Error creating documents user_id_category_created_at index: %v", err)
	}

	log.Println("Database initialized successfully.")
}

// --- Main Function ---
func main() {
	initDB()
	defer db.Close()

	if _, err := os.Stat(uploadsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(uploadsDir, 0755); err != nil { // Use MkdirAll
			log.Fatalf("Error creating uploads directory: %v", err)
		}
	}

	http.HandleFunc("/auth/register", registerHandler)
	http.HandleFunc("/auth/login", loginHandler)
	http.HandleFunc("/documents", documentsHandler)
	http.HandleFunc("/documents/", documentHandler)
	http.HandleFunc("/categories", authMiddleware(listCategoriesHandler)) // New route

	log.Println("Document service starting on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// --- Password & JWT Utilities (mostly unchanged) ---
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateJWT(userID string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// --- Auth Handlers (modified for DB) ---
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	if creds.Username == "" || creds.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	hashedPassword, err := hashPassword(creds.Password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	// Generate unique user ID (could use UUID library for better uniqueness)
	// For simplicity, using a timestamp-based approach here, but not recommended for production
	userID := fmt.Sprintf("user-%d", time.Now().UnixNano())


	stmt, err := db.Prepare("INSERT INTO users(id, username, password_hash) VALUES(?, ?, ?)")
	if err != nil {
		http.Error(w, "Error preparing statement: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(userID, creds.Username, hashedPassword)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: users.username") {
			http.Error(w, "Username already taken", http.StatusConflict)
		} else {
			http.Error(w, "Error creating user: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("User registered: %s (ID: %s)", creds.Username, userID)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": userID, "username": creds.Username})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	var storedID, storedHash string
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE username = ?", creds.Username).Scan(&storedID, &storedHash)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		} else {
			http.Error(w, "Error querying user: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if !checkPasswordHash(creds.Password, storedHash) {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	tokenString, err := generateJWT(storedID)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	log.Printf("User logged in: %s (ID: %s)", creds.Username, storedID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString, "userId": storedID, "username": creds.Username})
}

// --- Context Key for UserID ---
type contextKey string
const userIDContextKey = contextKey("userID")

// --- Middleware (modified to pass UserID via context) ---
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenStr == authHeader {
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add userID to context
		ctx := context.WithValue(r.Context(), userIDContextKey, claims.UserID)
		log.Printf("Authenticated user: %s for %s %s", claims.UserID, r.Method, r.URL.Path)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// --- Document Handlers (modified for DB & UserID) ---
func documentsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet: // Now protected to list only user's documents
		authMiddleware(listDocuments).ServeHTTP(w, r)
	case http.MethodPost:
		authMiddleware(uploadDocument).ServeHTTP(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func documentHandler(w http.ResponseWriter, r *http.Request) {
	docIDFromPath := filepath.Base(r.URL.Path)
	switch r.Method {
	case http.MethodGet: // Protected to download only user's document
		authMiddleware(func(res http.ResponseWriter, req *http.Request) {
			downloadDocument(res, req, docIDFromPath)
		}).ServeHTTP(w, r)
	case http.MethodDelete:
		authMiddleware(func(res http.ResponseWriter, req *http.Request) {
			deleteDocument(res, req, docIDFromPath)
		}).ServeHTTP(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func listDocuments(w http.ResponseWriter, r *http.Request) {
	currentUserID, ok := r.Context().Value(userIDContextKey).(string)
	if !ok || currentUserID == "" {
		http.Error(w, "User ID not found in token", http.StatusUnauthorized)
		return
	}

	searchQuery := r.URL.Query().Get("q")
	categoryQuery := r.URL.Query().Get("category") // New category filter

	var rows *sql.Rows
	var err error

	sqlQuery := "SELECT id, name, user_id, category, file_path FROM documents WHERE user_id = ?"
	args := []interface{}{currentUserID}

	if searchQuery != "" {
		sqlQuery += " AND LOWER(name) LIKE LOWER(?)"
		args = append(args, "%"+searchQuery+"%")
	}
	if categoryQuery != "" {
		sqlQuery += " AND category = ?"
		args = append(args, categoryQuery)
	}
	sqlQuery += " ORDER BY category, name" // Order by category then name


	rows, err = db.Query(sqlQuery, args...)
	if err != nil {
		http.Error(w, "Error querying documents: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	docList := make([]Document, 0)
	for rows.Next() {
		var doc Document
		// Scan category along with other fields
		if err := rows.Scan(&doc.ID, &doc.Name, &doc.UserID, &doc.Category, &doc.FilePath); err != nil {
			log.Printf("Error scanning document row: %v", err) // Log and continue
			continue
		}
		docList = append(docList, doc)
	}
	if err = rows.Err(); err != nil {
		http.Error(w, "Error iterating document rows: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(docList)
}

func uploadDocument(w http.ResponseWriter, r *http.Request) {
	currentUserID, ok := r.Context().Value(userIDContextKey).(string)
	if !ok || currentUserID == "" {
		http.Error(w, "User ID not found in token", http.StatusUnauthorized)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10 MB limit
		http.Error(w, "Error parsing multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving the file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Sanitize filename to prevent path traversal or invalid characters
	safeFilename := filepath.Base(handler.Filename)
	// Consider further sanitization or generating unique filenames

	// Create user-specific subdirectory if it doesn't exist
	userUploadsDir := filepath.Join(uploadsDir, currentUserID)
	if err := os.MkdirAll(userUploadsDir, 0755); err != nil {
		http.Error(w, "Error creating user upload directory: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Use a unique ID for the document to avoid filename clashes if desired, or prefix with user
	// For now, using original (sanitized) filename within user's folder
	docID := fmt.Sprintf("doc-%d", time.Now().UnixNano())
	filePath := filepath.Join(userUploadsDir, docID + "-" + safeFilename) // Store with unique docID prefix

	// Get category from form data
	category := r.FormValue("category") // Default is empty string if not provided

	dst, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Error creating the file on server: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Error saving the file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	stmt, err := db.Prepare("INSERT INTO documents(id, name, file_path, user_id, category) VALUES(?, ?, ?, ?, ?)")
	if err != nil {
		http.Error(w, "Error preparing document insert statement: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	_, err = stmt.Exec(docID, safeFilename, filePath, currentUserID, category)
	if err != nil {
		// Attempt to remove the orphaned file if DB insert fails
		os.Remove(filePath)
		http.Error(w, "Error saving document metadata: "+err.Error(), http.StatusInternalServerError)
		return
	}

	newDoc := Document{ID: docID, Name: safeFilename, UserID: currentUserID, Category: category, FilePath: filePath}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newDoc) // Return newDoc, which includes UserID and Category
	log.Printf("Uploaded document: %s (ID: %s, Category: %s) by User: %s", newDoc.Name, newDoc.ID, newDoc.Category, newDoc.UserID)
}

func downloadDocument(w http.ResponseWriter, r *http.Request, docID string) {
	currentUserID, ok := r.Context().Value(userIDContextKey).(string)
	if !ok || currentUserID == "" {
		http.Error(w, "User ID not found in token", http.StatusUnauthorized)
		return
	}

	var filePath, ownerUserID string
	err := db.QueryRow("SELECT file_path, user_id FROM documents WHERE id = ?", docID).Scan(&filePath, &ownerUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Document not found", http.StatusNotFound)
		} else {
			http.Error(w, "Error querying document for download: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if ownerUserID != currentUserID {
		http.Error(w, "Forbidden: You do not own this document", http.StatusForbidden)
		return
	}

	// Security: Ensure filePath is within the expected uploads directory
	// This is a basic check; more robust validation might be needed.
	absUploadsDir, _ := filepath.Abs(uploadsDir)
	absFilePath, _ := filepath.Abs(filePath)
	if !strings.HasPrefix(absFilePath, absUploadsDir) {
		log.Printf("Attempt to access file outside uploads directory: %s (requested by %s)", filePath, currentUserID)
		http.Error(w, "Invalid file path", http.StatusForbidden)
		return
	}


	http.ServeFile(w, r, filePath)
}

func deleteDocument(w http.ResponseWriter, r *http.Request, docID string) {
	currentUserID, ok := r.Context().Value(userIDContextKey).(string)
	if !ok || currentUserID == "" {
		http.Error(w, "User ID not found in token", http.StatusUnauthorized)
		return
	}

	var filePath, ownerUserID string
	err := db.QueryRow("SELECT file_path, user_id FROM documents WHERE id = ?", docID).Scan(&filePath, &ownerUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Document not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error querying document for deletion: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if ownerUserID != currentUserID {
		http.Error(w, "Forbidden: You do not own this document", http.StatusForbidden)
		return
	}

	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Failed to start transaction: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec("DELETE FROM documents WHERE id = ? AND user_id = ?", docID, currentUserID)
	if err != nil {
		tx.Rollback()
		http.Error(w, "Error deleting document metadata: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = os.Remove(filePath)
	if err != nil {
		// If file removal fails, roll back DB change to maintain consistency.
		// Or, decide if DB entry should be removed even if file is orphaned (depends on policy).
		tx.Rollback()
		log.Printf("Error deleting file %s: %v. DB transaction rolled back.", filePath, err)
		http.Error(w, "Error deleting document file, database change rolled back: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err = tx.Commit(); err != nil {
		// This is tricky: file deleted, but DB commit failed.
		// Log this serious issue. Manual intervention might be needed.
		log.Printf("CRITICAL: File %s deleted, but DB commit failed: %v", filePath, err)
		http.Error(w, "File deleted, but failed to commit database changes: "+err.Error(), http.StatusInternalServerError)
		return
	}


	w.WriteHeader(http.StatusNoContent)
	log.Printf("Deleted document: %s (ID: %s) by User: %s", filePath, docID, currentUserID)
}
