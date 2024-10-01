package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	port                string        = ":8080"
	otpLength           int           = 8
	expiry              time.Duration = 5 * time.Minute
	expiryCheckInterval time.Duration = time.Minute
)

var (
	users = make(map[string]*user)
	mu    sync.Mutex
)

type user struct {
	conn    net.Conn
	lastReq time.Time
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "httcp is running\n\n")

		fmt.Fprintln(w, "GET /{proto}/{address} - returns a one time password in plain text that identifies your connection")
		fmt.Fprintln(w, "POST /{otp} - takes body content and sends it to connection")
		fmt.Fprintln(w, "GET /{otp} - will read connection and return it as plain text")
	})
	http.HandleFunc("/{proto}/{address}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		if r.Method != http.MethodGet {
			codeWrite(w, fmt.Errorf("405: method not allowed"), http.StatusMethodNotAllowed)
			return
		}

		proto := r.PathValue("proto")
		address := r.PathValue("address")

		conn, err := net.Dial(proto, address)
		if err != nil {
			codeWrite(w, err, http.StatusInternalServerError)
			return
		}

		bytes := make([]byte, hex.DecodedLen(otpLength))

		_, err = rand.Read(bytes)
		if err != nil {
			codeWrite(w, err, http.StatusInternalServerError)
			return
		}
		otp := hex.EncodeToString(bytes)

		mu.Lock()
		users[otp] = &user{
			conn:    conn,
			lastReq: time.Now(),
		}
		mu.Unlock()

		fmt.Fprint(w, otp)
	})
	http.HandleFunc("/{otp}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		otp := r.PathValue("otp")

		if otp == "" {
			codeWrite(w, fmt.Errorf("otp empty"), http.StatusBadRequest)
			return
		}
		if users[otp] == nil {
			codeWrite(w, fmt.Errorf("invalid otp"), http.StatusForbidden)
			return
		}

		user := users[otp]
		user.lastReq = time.Now()

		switch r.Method {
		case http.MethodGet:
			buffer := make([]byte, 4096)
			n, err := user.conn.Read(buffer)
			if err != nil {
				codeWrite(w, err, http.StatusInternalServerError)
				return
			}

			w.Write(buffer[:n])
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				codeWrite(w, err, http.StatusInternalServerError)
				return
			}

			if _, err := user.conn.Write(body); err != nil {
				codeWrite(w, err, http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusNoContent)
		default:
			codeWrite(w, fmt.Errorf("405: method not allowed"), http.StatusMethodNotAllowed)
			return
		}
	})

	go func() {
		for range time.NewTicker(expiryCheckInterval).C {
			mu.Lock()

			for otp, user := range users {
				if time.Since(user.lastReq) > expiry {
					user.conn.Close()
					delete(users, otp)
				}
			}

			mu.Unlock()
		}
	}()

	http.ListenAndServe(port, nil)
}

func codeWrite(w http.ResponseWriter, err error, statusCode int) {
	w.WriteHeader(statusCode)
	fmt.Fprint(w, err)
}
