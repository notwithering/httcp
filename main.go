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
		log(0, "the password \"password\" is shown explicitly as an example at website root. very insecure password")
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		if r.Method != http.MethodGet {
			codeWrite(w, r, fmt.Errorf("405: method not allowed"), http.StatusMethodNotAllowed)
			return
		}

		fmt.Fprint(w, "httcp is running\n\n")

		fmt.Fprint(w, "GET  /info          - returns server info in json\n")
		fmt.Fprint(w, "GET  /new/{address} - creates a new connection and returns a one-time password\n")
		fmt.Fprint(w, "GET  /read/{otp}    - recieve data from connection\n")
		fmt.Fprint(w, "POST /write/{otp}   - send data to connection\n")
		fmt.Fprint(w, "POST /ping/{otp}    - reset connection timeout\n")
		fmt.Fprint(w, "POST /close/{otp}   - close connection\n")

		if cli.Password != "" {
			fmt.Fprint(w, "\nserver requires password \"auth\" parameter (e.g. ?auth=password)")
		}
	})
	http.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if checkMethod(w, r, http.MethodGet) {
			return
		}

		fmt.Fprintf(w, `{"code":0,"otp":{"length":%d,"ttl":%f},"requirePassword":%v}`, cli.OTPLength, cli.TTL.Seconds(), cli.Password != "")
	})
	http.HandleFunc("/new/{address}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		if checkMethod(w, r, http.MethodGet) {
			return
		}

		if !isAuthed(w, r) {
			return
		}

		address := r.PathValue("address")

		log(1, fmt.Sprintf("dialing tcp://%s", address))
		conn, err := net.Dial("tcp", address)
		if err != nil {
			log(1, fmt.Sprintf("could not dial tcp://%s:", address), err)
			codeWrite(w, r, err, http.StatusInternalServerError)
			return
		}

		bytes := make([]byte, hex.DecodedLen(cli.OTPLength))
		var otp string

		log(1, "generating otp")

		for {
			_, err = rand.Read(bytes)
			if err != nil {
				log(1, "error while reading rand:", err)
				codeWrite(w, r, err, http.StatusInternalServerError)
				return
			}
			otp = hex.EncodeToString(bytes)

			if users[otp] == nil {
				break
			}

			log(1, fmt.Sprintf("otp %s already exists, regenerating", otp))
		}

		mu.Lock()
		log(1, "locked mutex")

		log(1, fmt.Sprintf("assigning user %s to slice", otp))
		users[otp] = &user{
			conn:    conn,
			lastReq: time.Now(),
		}

		mu.Unlock()
		log(1, "unlocked mutex")

		fmt.Fprint(w, otp)
	})
	http.HandleFunc("/read/{otp}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		if checkMethod(w, r, http.MethodGet) {
			return
		}

		if !isAuthed(w, r) {
			return
		}

		otp, exit := getOTP(w, r)
		if exit {
			return
		}
		u := users[otp]

		u.lastReq = time.Now()

		log(1, "reading user conn")

		buffer := make([]byte, 4096)
		n, err := u.conn.Read(buffer)
		if err != nil {
			codeWrite(w, r, err, http.StatusInternalServerError)
			return
		}

		log(1, "writing user conn buffer to user")
		w.Write(buffer[:n])
	})
	http.HandleFunc("/write/{otp}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		if checkMethod(w, r, http.MethodPost) {
			return
		}

		if !isAuthed(w, r) {
			return
		}

		otp, exit := getOTP(w, r)
		if exit {
			return
		}
		u := users[otp]

		u.lastReq = time.Now()

		log(1, "reading request body")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			codeWrite(w, r, err, http.StatusInternalServerError)
			return
		}

		log(1, "writing request body to user conn")
		if _, err := u.conn.Write(body); err != nil {
			codeWrite(w, r, err, http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
	http.HandleFunc("/ping/{otp}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		if checkMethod(w, r, http.MethodPost) {
			return
		}

		if !isAuthed(w, r) {
			return
		}

		otp, exit := getOTP(w, r)
		if exit {
			return
		}
		u := users[otp]

		u.lastReq = time.Now()

		w.WriteHeader(http.StatusNoContent)
	})
	http.HandleFunc("/close/{otp}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		if checkMethod(w, r, http.MethodPost) {
			return
		}

		if !isAuthed(w, r) {
			return
		}

		otp, exit := getOTP(w, r)
		if exit {
			return
		}
		u := users[otp]

		u.conn.Close()

		mu.Lock()
		users[otp] = nil
		mu.Unlock()

		w.WriteHeader(http.StatusNoContent)
	})

	go func() {
		for range time.NewTicker(cli.ExpiryCheckInterval).C {
			mu.Lock()
			log(1, "locked mutex")

			log(1, "preforming routine expiry check")

			for otp, user := range users {
				if time.Since(user.lastReq) > cli.TTL {
					user.conn.Close()
					log(1, fmt.Sprintf("closed user %s conn", otp))
					delete(users, otp)
					log(1, "deleted user", otp)
				}
			}

			mu.Unlock()
			log(1, "unlocked mutex")
		}
	}()

	log(1, "started server")

	http.ListenAndServe(cli.Host+":"+cli.Port, nil)
}

func checkMethod(w http.ResponseWriter, r *http.Request, meth string) (exit bool) {
	if r.Method != meth {
		codeWrite(w, r, fmt.Errorf("405: method not allowed"), http.StatusMethodNotAllowed)
		return true
	}

	return false
}

func isAuthed(w http.ResponseWriter, r *http.Request) bool {
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

func getOTP(w http.ResponseWriter, r *http.Request) (otp string, exit bool) {
	otp = r.PathValue("otp")
	exit = true

	if otp == "" {
		codeWrite(w, r, fmt.Errorf("otp empty"), http.StatusBadRequest)
		return
	}
	if users[otp] == nil {
		codeWrite(w, r, fmt.Errorf("invalid otp"), http.StatusForbidden)
		return
	}

	return otp, false
}

func codeWrite(w http.ResponseWriter, r *http.Request, err error, statusCode int) {
	log(1, fmt.Sprintf("%s <- %s", r.RemoteAddr, err.Error()))
	w.WriteHeader(statusCode)
	fmt.Fprint(w, err)
}

func log(level int, a ...any) {
	var verbosity int
	for i, l := range []bool{true /*no verbosity*/, cli.Verbose} { // will eventually add very verbose flag
		if l {
			verbosity = i
		}
	}

	if level > verbosity {
		return
	}

	fmt.Printf("[%s] ", time.Now().Format(time.DateTime))
	fmt.Println(a...)
}
