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

	"github.com/alecthomas/kong"
)

var cli struct {
	Host                string        `help:"The host to bind to." short:"h" env:"HOST" default:"0.0.0.0"`
	Port                string        `help:"The port to serve." short:"p" env:"PORT" default:"8080"`
	TLS                 bool          `help:"Enable TLS." short:"t"`
	Cert                string        `help:"Path to TLS certificate file." short:"c" env:"TLS_CERT" type:"existingfile"`
	Key                 string        `help:"Path to TLS key file." short:"k" env:"TLS_KEY" type:"existingfile"`
	OTPLength           int           `help:"Length of one-time password." short:"o" default:"8"`
	TTL                 time.Duration `help:"How long a stale connection can live." short:"T" default:"5m"`
	ExpiryCheckInterval time.Duration `help:"How long to wait before checking for stale connections again." short:"E" default:"1m"`
	Verbose             bool          `help:"Print more messages." short:"v"`
	Password            string        `help:"Require password parameter in requests." short:"P" default:""`
}

var (
	users = make(map[string]*user)
	mu    sync.Mutex
)

type user struct {
	conn    net.Conn
	lastReq time.Time
}

var kctx *kong.Context

func main() {
	kctx = kong.Parse(&cli)

	if cli.Password == "password" {
		fmt.Println("warning: the password \"password\" is shown explicitly as an example at website root. very insecure password")
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "httcp is running\n\n")

		fmt.Fprint(w, "GET /json/info - provides info about the inner workings of the server that you may want to know\n")
		fmt.Fprint(w, "GET /tcp/{address} - returns a one time password in plain text that identifies your connection\n")
		fmt.Fprint(w, "POST /{otp} - takes body content and sends it to connection\n")
		fmt.Fprint(w, "GET /{otp} - will read connection and return it as plain text\n")

		if cli.Password != "" {
			fmt.Fprint(w, "\nserver requires password \"auth\" parameter (e.g. ?auth=password)")
		}
	})
	http.HandleFunc("/tcp/{address}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		if !auth(w, r) {
			return
		}

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

		bytes := make([]byte, hex.DecodedLen(cli.OTPLength))
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

		if !auth(w, r) {
			return
		}

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

		fmt.Fprintf(w, `{"code":0,"otp":{"length":%d,"ttl":%f},"requirePassword":%v}`, cli.OTPLength, cli.TTL.Seconds(), cli.Password != "")
	})

	go func() {
		for range time.NewTicker(cli.ExpiryCheckInterval).C {
			mu.Lock()
			vbLog("locked mutex")

			vbLog("preforming routine expiry check")

			for otp, user := range users {
				if time.Since(user.lastReq) > cli.TTL {
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

	http.ListenAndServe(cli.Host+":"+cli.Port, nil)
}

func codeWrite(w http.ResponseWriter, r *http.Request, err error, statusCode int) {
	vbLog(fmt.Sprintf("%s <- %s", r.RemoteAddr, err.Error()))
	w.WriteHeader(statusCode)
	fmt.Fprint(w, err)
}

func vbLog(a ...any) {
	if !cli.Verbose {
		return
	}

	fmt.Printf("[%s] ", time.Now().Format(time.DateTime))
	fmt.Println(a...)
}

func auth(w http.ResponseWriter, r *http.Request) bool {
	authed := func() bool {
		if cli.Password == "" {
			return true
		}

		auth := r.URL.Query().Get("auth")
		if auth != cli.Password {
			return false
		}

		return true
	}()

	if !authed {
		http.Error(w, "401: unauthorized", http.StatusUnauthorized)
	}

	return authed
}
