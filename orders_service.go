// CWE-89: SQL Injection
// Vulnerable: query string built with fmt.Sprintf using raw user input.
package main

import (
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"

	_ "github.com/lib/pq"
)

// allowedAvatarHosts is the allow-list of hosts the avatar fetcher may reach.
var allowedAvatarHosts = map[string]bool{
	"avatars.example.com": true,
}

func searchOrdersHandler(w http.ResponseWriter, r *http.Request) {
	connStr := fmt.Sprintf("host=localhost dbname=orders user=%s password=%s sslmode=disable",
		os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"))
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer db.Close()

	customerID := r.URL.Query().Get("customer_id")

	// FIXED: parameterized query using a placeholder instead of string formatting
	rows, err := db.Query("SELECT id, total, status FROM orders WHERE customer_id = $1", customerID)
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

// isSafeAvatarURL rejects non-http(s) schemes, hosts not on the allow-list,
// and hosts that resolve to private/loopback/link-local addresses.
func isSafeAvatarURL(rawURL string) (*url.URL, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, false
	}
	if !allowedAvatarHosts[parsed.Hostname()] {
		return nil, false
	}
	ips, err := net.LookupIP(parsed.Hostname())
	if err != nil || len(ips) == 0 {
		return nil, false
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return nil, false
		}
	}
	return parsed, true
}

func fetchAvatarHandler(w http.ResponseWriter, r *http.Request) {
	avatarURL := r.URL.Query().Get("url")
	// FIXED: validate the target URL against an allow-list of permitted hosts
	// and block private/loopback/link-local addresses before fetching (SSRF).
	safeURL, ok := isSafeAvatarURL(avatarURL)
	if !ok {
		http.Error(w, "invalid or disallowed avatar URL", 400)
		return
	}
	resp, err := http.Get(safeURL.String())
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
