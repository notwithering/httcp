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
	verbose             bool          = true
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

		fmt.Fprintln(w, "GET /json/info - provides info about the inner workings of the server that you may want to know")
		fmt.Fprintln(w, "GET /tcp/{address} - returns a one time password in plain text that identifies your connection")
		fmt.Fprintln(w, "POST /{otp} - takes body content and sends it to connection")
		fmt.Fprintln(w, "GET /{otp} - will read connection and return it as plain text")
	})
	http.HandleFunc("/{proto}/{address}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		if r.Method != http.MethodGet {
			codeWrite(w, r, fmt.Errorf("405: method not allowed"), http.StatusMethodNotAllowed)
			return
		}

		address := r.PathValue("address")

		vbLog(fmt.Sprintf("dialing tcp://%s", address))
		conn, err := net.Dial("tcp", address)
		if err != nil {
			vbLog(fmt.Sprintf("could not dial tcp://%s:", address), err)
			codeWrite(w, r, err, http.StatusInternalServerError)
			return
		}

		bytes := make([]byte, hex.DecodedLen(otpLength))
		var otp string

		vbLog("generating otp")

		for {
			_, err = rand.Read(bytes)
			if err != nil {
				vbLog("error while reading rand:", err)
				codeWrite(w, r, err, http.StatusInternalServerError)
				return
			}
			otp = hex.EncodeToString(bytes)

			if users[otp] == nil {
				break
			}

			vbLog(fmt.Sprintf("otp %s already exists, regenerating", otp))
		}

		mu.Lock()
		vbLog("locked mutex")

		vbLog(fmt.Sprintf("assigning user %s to slice", otp))
		users[otp] = &user{
			conn:    conn,
			lastReq: time.Now(),
		}

		mu.Unlock()
		vbLog("unlocked mutex")

		fmt.Fprint(w, otp)
	})
	http.HandleFunc("/{otp}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		otp := r.PathValue("otp")

		if otp == "" {
			codeWrite(w, r, fmt.Errorf("otp empty"), http.StatusBadRequest)
			return
		}
		if users[otp] == nil {
			codeWrite(w, r, fmt.Errorf("invalid otp"), http.StatusForbidden)
			return
		}

		user := users[otp]
		user.lastReq = time.Now()

		switch r.Method {
		case http.MethodGet:
			vbLog("reading user conn")

			buffer := make([]byte, 4096)
			n, err := user.conn.Read(buffer)
			if err != nil {
				codeWrite(w, r, err, http.StatusInternalServerError)
				return
			}

			vbLog("writing user conn buffer to user")
			w.Write(buffer[:n])
		case http.MethodPost:
			vbLog("reading request body")
			body, err := io.ReadAll(r.Body)
			if err != nil {
				codeWrite(w, r, err, http.StatusInternalServerError)
				return
			}

			vbLog("writing request body to user conn")
			if _, err := user.conn.Write(body); err != nil {
				codeWrite(w, r, err, http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusNoContent)
		default:
			codeWrite(w, r, fmt.Errorf("405: method not allowed"), http.StatusMethodNotAllowed)
			return
		}
	})
	http.HandleFunc("/json/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodGet {
			codeWrite(w, r, fmt.Errorf(`{"code":1,"error":"405: method not allowed"}`), http.StatusMethodNotAllowed)
			return
		}

		fmt.Fprintf(w, `{"code":0,"otp":{"length":%d,"ttl":%f}}`, otpLength, expiry.Seconds())
	})

	go func() {
		for range time.NewTicker(expiryCheckInterval).C {
			mu.Lock()
			vbLog("locked mutex")

			vbLog("preforming routine expiry check")

			for otp, user := range users {
				if time.Since(user.lastReq) > expiry {
					user.conn.Close()
					vbLog(fmt.Sprintf("closed user %s conn", otp))
					delete(users, otp)
					vbLog("deleted user", otp)
				}
			}

			mu.Unlock()
			vbLog("unlocked mutex")
		}
	}()

	vbLog("started server")

	http.ListenAndServe(port, nil)
}

func codeWrite(w http.ResponseWriter, r *http.Request, err error, statusCode int) {
	vbLog(fmt.Sprintf("%s <- %s", r.RemoteAddr, err.Error()))
	w.WriteHeader(statusCode)
	fmt.Fprint(w, err)
}

func vbLog(a ...any) {
	if !verbose {
		return
	}

	fmt.Printf("[%s] ", time.Now().Format(time.DateTime))
	fmt.Println(a...)
}
