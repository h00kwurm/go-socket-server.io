package socketio

import (
	// "code.google.com/p/go.net/websocket"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/julienschmidt/httprouter"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	DEFAULT_TIMEOUT = 60
	DEFAULT_PORT    = 8080

	SOCKETIO_BASE_SUFFIX      = "/socket.io/1/"
	SOCKETIO_WEBSOCKET_SUFFIX = "/socket.io/1/websocket/:session"

	NOT_FOUND    = "These are not the pages you're looking for ..."
	UNAUTHORIZED = "Sorry, I cannot do that dave"
)

var (
	uriRegexp = regexp.MustCompile(`^(.+?)/(1)(?:/([^/]+)/([^/]+))?/?$`)
	upgrader  = websocket.Upgrader{
		ReadBufferSize:  2048,
		WriteBufferSize: 2048,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
)

type Config struct {
	Port             int
	HeartbeatTimeout int
	ClosingTimeout   int
	NewSessionID     func() string
	Transports       *TransportManager
	AuthFunction     func(map[string]string) bool
	IsSecure         bool
	SecureCertPath   string
	SecureKeyPath    string
}

type SocketIOServer struct {
	// *http.ServeMux
	mutex            sync.RWMutex
	heartbeatTimeout int
	closingTimeout   int
	isAuthorized     func(map[string]string) bool
	newSessionId     func() string
	transports       *TransportManager
	sessions         map[string]*Session
	eventEmitters    map[string]*EventEmitter
	isSecure         bool
	certPath         string
	keyPath          string
	port             int
}

func NewSocketIOServer(config *Config) *SocketIOServer {
	server := &SocketIOServer{}
	if config != nil {
		server.heartbeatTimeout = config.HeartbeatTimeout
		server.closingTimeout = config.ClosingTimeout
		server.newSessionId = config.NewSessionID
		server.transports = config.Transports
		server.isAuthorized = config.AuthFunction
		server.port = config.Port
		if config.IsSecure {
			server.isSecure = true
			if fileExists(config.SecureCertPath) && fileExists(config.SecureKeyPath) {
				server.keyPath, server.certPath = config.SecureKeyPath, config.SecureCertPath
			} else {
				panic("chose secure but gave invalid cert path or key path")
			}
		}
	}
	if server.heartbeatTimeout == 0 {
		server.heartbeatTimeout = DEFAULT_TIMEOUT
	}
	upgrader.HandshakeTimeout = time.Duration(server.heartbeatTimeout) * time.Millisecond
	if server.closingTimeout == 0 {
		server.closingTimeout = DEFAULT_TIMEOUT
	}
	if server.newSessionId == nil {
		server.newSessionId = NewSessionID
	}
	if server.transports == nil {
		server.transports = DefaultTransports
	}
	if server.port == 0 {
		server.port = DEFAULT_PORT
	}

	server.sessions = make(map[string]*Session)
	server.eventEmitters = make(map[string]*EventEmitter)
	return server
}

func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		return !os.IsNotExist(err)
	}
	return true
}

func (srv *SocketIOServer) StartServer() {

	router := httprouter.New()
	router.NotFound = NotFoundHandler

	router.GET(SOCKETIO_BASE_SUFFIX, srv.handShake)
	router.POST(SOCKETIO_BASE_SUFFIX, srv.handShake)

	router.GET(SOCKETIO_WEBSOCKET_SUFFIX, srv.websocketConnection)

	if srv.isSecure {
		// http.ListenAndServeTLS(fmt.Sprintf(":%v", srv.port), srv.certPath, srv.keyPath, nil)
	} else {
		http.ListenAndServe(fmt.Sprintf(":%v", srv.port), router)
	}

}

func NotFoundHandler(rw http.ResponseWriter, req *http.Request) {
	io.WriteString(rw, NOT_FOUND)
}

// func (srv *SocketIOServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
// 	path := r.URL.Path
// 	if !strings.HasPrefix(path, "/socket.io/1/") {

// 		cookie, _ := r.Cookie("socket.io.sid")
// 		if cookie == nil {
// 			http.SetCookie(w, &http.Cookie{
// 				Name:  "socket.io.sid",
// 				Value: NewSessionID(),
// 				Path:  "/",
// 			})
// 		}
// 		srv.ServeMux.ServeHTTP(w, r)
// 		return
// 	}
// 	path = path[len("/socket.io/1/"):]
// 	if path == "" {
// 		srv.handShake(w, r)
// 		return
// 	}

// 	spliter := strings.SplitN(path, "/", 2)
// 	if len(spliter) < 2 {
// 		http.NotFound(w, r)
// 		return
// 	}

// 	transportName, sessionId := spliter[0], spliter[1]
// 	if transportName != "websocket" {
// 		http.Error(w, "not websocket", http.StatusBadRequest)
// 		return
// 	}

// 	session := srv.getSession(sessionId)
// 	if session == nil {
// 		http.Error(w, "invalid session id", http.StatusBadRequest)
// 		return
// 	}

// 	// open
// 	transport := newWebSocket(session)

// 	websocket.Handler(transport.webSocketHandler).ServeHTTP(w, r)
// }

func (srv *SocketIOServer) websocketConnection(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	io.WriteString(w, "fuck off")

	// conn, err := upgrader.Upgrade(w, r, nil)
	// if err != nil {
	// 	fmt.Println(err)
	// 	panic("error upgrading connection")
	// }

	// go func() {
	// 	readLoop(conn)
	// 	defer conn.Close()
	// }()
}

func readLoop(c *websocket.Conn) {
	for {
		_, r, err := c.NextReader()
		if err != nil {
			fmt.Println("error in readloop read")
			fmt.Println(err)
			c.Close()
			break
		}
		fmt.Println("got message: " + fmt.Sprintf("%v", r))
	}
}

func (srv *SocketIOServer) Of(name string) *EventEmitter {
	ret, ok := srv.eventEmitters[name]
	if !ok {
		ret = NewEventEmitter()
		srv.eventEmitters[name] = ret
	}
	return ret
}

func (srv *SocketIOServer) In(name string) *Broadcaster {
	namespaces := []*NameSpace{}
	for _, session := range srv.sessions {
		ns := session.Of(name)
		if ns != nil {
			namespaces = append(namespaces, ns)
		}
	}

	return &Broadcaster{Namespaces: namespaces}
}

func (srv *SocketIOServer) Broadcast(name string, args ...interface{}) {
	srv.In("").Broadcast(name, args...)
}

func (srv *SocketIOServer) Except(ns *NameSpace) *Broadcaster {
	return srv.In("").Except(ns)
}

func (srv *SocketIOServer) On(name string, fn interface{}) error {
	return srv.Of("").On(name, fn)
}

func (srv *SocketIOServer) RemoveListener(name string, fn interface{}) {
	srv.Of("").RemoveListener(name, fn)
}

func (srv *SocketIOServer) RemoveAllListeners(name string) {
	srv.Of("").RemoveAllListeners(name)
}

func (srv *SocketIOServer) handShake(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("origin"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if srv.isAuthorized != nil {
		params := make(map[string]string)
		for key, val := range r.URL.Query() {
			params[key] = val[0]
		}
		if !srv.isAuthorized(params) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(UNAUTHORIZED))
			return
		}
	}

	sessionId := NewSessionID()

	transportNames := srv.transports.GetTransportNames()
	fmt.Fprintf(w, "%s:%d:%d:%s",
		sessionId,
		srv.heartbeatTimeout,
		srv.closingTimeout,
		strings.Join(transportNames, ","))

	session := srv.getSession(sessionId)
	if session == nil {
		session = NewSession(srv.eventEmitters, sessionId, srv.heartbeatTimeout, true, r)
		srv.addSession(session)
	}
}

func (srv *SocketIOServer) addSession(ss *Session) {
	srv.mutex.Lock()
	defer srv.mutex.Unlock()
	srv.sessions[ss.SessionId] = ss
}

func (srv *SocketIOServer) removeSession(ss *Session) {
	srv.mutex.Lock()
	defer srv.mutex.Unlock()
	delete(srv.sessions, ss.SessionId)
}

func (srv *SocketIOServer) getSession(sessionId string) *Session {
	srv.mutex.RLock()
	defer srv.mutex.RUnlock()
	return srv.sessions[sessionId]
}
