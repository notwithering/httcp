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

		fmt.Fprint(w, "/{proto}/{address} - returns a one time password in plain text\n")
		fmt.Fprint(w, "example: GET /tcp/us.litecoinpool.org:3333 -> 10f880d9\n\n")

		fmt.Fprint(w, "/{otp} - takes body content and sends it to connection\n")
		fmt.Fprint(w, "example: GET /10f880d9 -> sends body to server and reads server and returns as plain text")
	})
	http.HandleFunc("/{proto}/{address}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		proto := r.PathValue("proto")
		address := r.PathValue("address")

		conn, err := net.Dial(proto, address)
		if err != nil {
			serverError(w, err, http.StatusInternalServerError)
			return
		}

		bytes := make([]byte, hex.DecodedLen(otpLength))

		_, err = rand.Read(bytes)
		if err != nil {
			serverError(w, err, http.StatusInternalServerError)
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
			serverError(w, fmt.Errorf("otp empty"), http.StatusBadRequest)
			return
		}
		if users[otp] == nil {
			serverError(w, fmt.Errorf("invalid otp"), http.StatusForbidden)
			return
		}

		user := users[otp]
		user.lastReq = time.Now()

		body, err := io.ReadAll(r.Body)
		if err != nil {
			serverError(w, err, http.StatusInternalServerError)
			return
		}

		if len(body) > 0 {
			if _, err := user.conn.Write(body); err != nil {
				serverError(w, err, http.StatusInternalServerError)
				return
			}
		}

		buffer := make([]byte, 4096)
		n, err := user.conn.Read(buffer)
		if err != nil {
			serverError(w, err, http.StatusInternalServerError)
			return
		}

		w.Write(buffer[:n])
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

func serverError(w http.ResponseWriter, err error, statusCode int) {
	w.WriteHeader(statusCode)
	fmt.Fprint(w, err)
}
