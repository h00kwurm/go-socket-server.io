##socket.io server library for Golang

This branch is compatible with socket.io 0.9.x.

forked from [http://code.google.com/p/go-socketio](http://code.google.com/p/go-socketio)
Documentation: http://godoc.org/github.com/googollee/go-socket.io
##Demo

**server:**

```go
package main

import (
  "fmt"
  "github.com/googollee/go-socket.io"
  "log"
  "net/http"
)

func news(ns *socketio.NameSpace, title, body string, article_num int) {
  var name string
  name = ns.Session.Values["name"].(string)
  fmt.Printf("%s said in %s, title: %s, body: %s, article number: %i", name, ns.Endpoint(), title, body, article_num)
}

func onConnect(ns *socketio.NameSpace) {
  fmt.Println("connected:", ns.Id(), " in channel ", ns.Endpoint())
  ns.Session.Values["name"] = "this guy"
  ns.Emit("news", "this is totally news", 3)
}

func onDisconnect(ns *socketio.NameSpace) {
  fmt.Println("disconnected:", ns.Id(), " in channel ", ns.Endpoint())
}

func main() {
  sock_config := &socketio.Config{}
  sock_config.HeartbeatTimeout = 2
  sock_config.ClosingTimeout = 4

  sio := socketio.NewSocketIOServer(sock_config)

  // Handler for new connections, also adds socket.io event handlers
  sio.On("connect", onConnect)
  sio.On("disconnect", onDisconnect)
  sio.On("news", news)
  sio.On("ping", func(ns *socketio.NameSpace){
    sio.Broadcast("pong", nil)
  })

  //in politics channel
  sio.Of("/pol").On("connect", onConnect)
  sio.Of("/pol").On("disconnect", onDisconnect)
  sio.Of("/pol").On("news", news)
  sio.Of("/pol").On("ping", func(ns *socketio.NameSpace){
    sio.In("/pol").Broadcast("pong", nil)
  })

  //this will serve a http static file server
  sio.Handle("/", http.FileServer(http.Dir("./public/")))
  //startup the server
  log.Fatal(http.ListenAndServe(":3000", sio))
}
```