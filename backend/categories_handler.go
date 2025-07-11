package main

import (
	"encoding/json"
	"log"
	"net/http"
)

func listCategoriesHandler(w http.ResponseWriter, r *http.Request) {
	currentUserID, ok := r.Context().Value(userIDContextKey).(string)
	if !ok || currentUserID == "" {
		http.Error(w, "User ID not found in token", http.StatusUnauthorized)
		return
	}

	rows, err := db.Query("SELECT DISTINCT category FROM documents WHERE user_id = ? AND category != '' ORDER BY category", currentUserID)
	if err != nil {
		http.Error(w, "Error querying categories: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	categories := make([]string, 0)
	for rows.Next() {
		var category string
		if err := rows.Scan(&category); err != nil {
			log.Printf("Error scanning category row: %v", err)
			continue
		}
		categories = append(categories, category)
	}
	if err = rows.Err(); err != nil {
		http.Error(w, "Error iterating category rows: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(categories)
}
