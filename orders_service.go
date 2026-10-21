// Fixed: CWE-89 SQL Injection and CWE-918 SSRF.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	_ "github.com/lib/pq"
)

var allowedAvatarHosts = map[string]bool{
	"images.example.com": true,
}

func isAllowedIP(ip net.IP) bool {
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsUnspecified()
}

func searchOrdersHandler(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("postgres", "host=localhost dbname=orders user=app password=app sslmode=disable")
	defer db.Close()

	customerID := r.URL.Query().Get("customer_id")

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

// safeAvatarClient pins the actual TCP connection to an address that is
// validated at dial time (not just at an earlier DNS lookup), so a DNS
// record that changes between validation and connection (DNS rebinding)
// cannot redirect the request to an internal address.
var safeAvatarClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("could not resolve host")
			}
			var validIP net.IP
			for _, ip := range ips {
				if isAllowedIP(ip) {
					validIP = ip
					break
				}
			}
			if validIP == nil {
				return nil, fmt.Errorf("host resolves to a disallowed network")
			}
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, network, net.JoinHostPort(validIP.String(), port))
		},
	},
}

func fetchAvatarHandler(w http.ResponseWriter, r *http.Request) {
	avatarURL := r.URL.Query().Get("url")
	parsed, err := url.Parse(avatarURL)
	if err != nil || parsed.Scheme != "https" || !allowedAvatarHosts[parsed.Hostname()] {
		http.Error(w, "url not allowed", 400)
		return
	}
	resp, err := safeAvatarClient.Get(parsed.String())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		http.Error(w, "redirects are not allowed", 400)
		return
	}
	io.Copy(w, resp.Body)
}

func main() {
	http.HandleFunc("/orders/search", searchOrdersHandler)
	http.HandleFunc("/avatar/fetch", fetchAvatarHandler)
	http.ListenAndServe(":8080", nil)
}
