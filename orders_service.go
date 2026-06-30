// CWE-89: SQL Injection
// Vulnerable: query string built with fmt.Sprintf using raw user input.
package main

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"

	_ "github.com/lib/pq"
)

func searchOrdersHandler(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("postgres", "host=localhost dbname=orders user=app password=app sslmode=disable")
	defer db.Close()

	customerID := r.URL.Query().Get("customer_id")

	// VULNERABLE: string formatting builds the SQL statement directly
	query := fmt.Sprintf("SELECT id, total, status FROM orders WHERE customer_id = '%s'", customerID)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id, status string
		var total float64
		rows.Scan(&id, &total, &status)
		fmt.Fprintf(w, "%s: $%.2f (%s)\n", id, total, status)
	}
}

func fetchAvatarHandler(w http.ResponseWriter, r *http.Request) {
	avatarURL := r.URL.Query().Get("url")
	// VULNERABLE: server fetches an arbitrary attacker-supplied URL (SSRF),
	// including internal-only endpoints like cloud metadata services.
	resp, err := http.Get(avatarURL)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func main() {
	http.HandleFunc("/orders/search", searchOrdersHandler)
	http.HandleFunc("/avatar/fetch", fetchAvatarHandler)
	http.ListenAndServe(":8080", nil)
}
