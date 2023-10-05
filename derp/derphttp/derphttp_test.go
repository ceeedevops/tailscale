// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/types/key"
)

func TestSendRecv(t *testing.T) {
	serverPrivateKey := key.NewNode()

	const numClients = 3
	var clientPrivateKeys []key.NodePrivate
	var clientKeys []key.NodePublic
	for i := 0; i < numClients; i++ {
		priv := key.NewNode()
		clientPrivateKeys = append(clientPrivateKeys, priv)
		clientKeys = append(clientKeys, priv.Public())
	}

	s := derp.NewServer(serverPrivateKey, t.Logf)
	defer s.Close()

	httpsrv := &http.Server{
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		Handler:      Handler(s),
	}

	ln, err := net.Listen("tcp4", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	serverURL := "http://" + ln.Addr().String()
	t.Logf("server URL: %s", serverURL)

	go func() {
		if err := httpsrv.Serve(ln); err != nil {
			if err == http.ErrServerClosed {
				return
			}
			panic(err)
		}
	}()

	var clients []*Client
	var recvChs []chan []byte
	done := make(chan struct{})
	var wg sync.WaitGroup
	defer func() {
		close(done)
		for _, c := range clients {
			c.Close()
		}
		wg.Wait()
	}()
	for i := 0; i < numClients; i++ {
		key := clientPrivateKeys[i]
		c, err := NewClient(key, serverURL, t.Logf)
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		if err := c.Connect(context.Background()); err != nil {
			t.Fatalf("client %d Connect: %v", i, err)
		}
		waitConnect(t, c)
		clients = append(clients, c)
		recvChs = append(recvChs, make(chan []byte))

		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				m, err := c.Recv()
				if err != nil {
					select {
					case <-done:
						return
					default:
					}
					t.Logf("client%d: %v", i, err)
					break
				}
				switch m := m.(type) {
				default:
					t.Errorf("unexpected message type %T", m)
					continue
				case derp.PeerGoneMessage:
					// Ignore.
				case derp.ReceivedPacket:
					recvChs[i] <- bytes.Clone(m.Data)
				}
			}
		}(i)
	}

	recv := func(i int, want string) {
		t.Helper()
		select {
		case b := <-recvChs[i]:
			if got := string(b); got != want {
				t.Errorf("client1.Recv=%q, want %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("client%d.Recv, got nothing, want %q", i, want)
		}
	}
	recvNothing := func(i int) {
		t.Helper()
		select {
		case b := <-recvChs[0]:
			t.Errorf("client%d.Recv=%q, want nothing", i, string(b))
		default:
		}
	}

	msg1 := []byte("hello 0->1\n")
	if err := clients[0].Send(clientKeys[1], msg1); err != nil {
		t.Fatal(err)
	}
	recv(1, string(msg1))
	recvNothing(0)
	recvNothing(2)

	msg2 := []byte("hello 1->2\n")
	if err := clients[1].Send(clientKeys[2], msg2); err != nil {
		t.Fatal(err)
	}
	recv(2, string(msg2))
	recvNothing(0)
	recvNothing(1)
}

func waitConnect(t testing.TB, c *Client) {
	t.Helper()
	if m, err := c.Recv(); err != nil {
		t.Fatalf("client first Recv: %v", err)
	} else if v, ok := m.(derp.ServerInfoMessage); !ok {
		t.Fatalf("client first Recv was unexpected type %T", v)
	}
}

func TestPing(t *testing.T) {
	serverPrivateKey := key.NewNode()
	s := derp.NewServer(serverPrivateKey, t.Logf)
	defer s.Close()

	httpsrv := &http.Server{
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		Handler:      Handler(s),
	}

	ln, err := net.Listen("tcp4", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	serverURL := "http://" + ln.Addr().String()
	t.Logf("server URL: %s", serverURL)

	go func() {
		if err := httpsrv.Serve(ln); err != nil {
			if err == http.ErrServerClosed {
				return
			}
			panic(err)
		}
	}()

	c, err := NewClient(key.NewNode(), serverURL, t.Logf)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()
	if err := c.Connect(context.Background()); err != nil {
		t.Fatalf("client Connect: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		for {
			m, err := c.Recv()
			if err != nil {
				errc <- err
				return
			}
			t.Logf("Recv: %T", m)
		}
	}()
	err = c.Ping(context.Background())
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func newTestServer(t *testing.T, k key.NodePrivate) (serverURL string, s *derp.Server) {
	s = derp.NewServer(k, t.Logf)
	httpsrv := &http.Server{
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		Handler:      Handler(s),
	}

	ln, err := net.Listen("tcp4", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	serverURL = "http://" + ln.Addr().String()
	s.SetMeshKey("1234")

	go func() {
		if err := httpsrv.Serve(ln); err != nil {
			if err == http.ErrServerClosed {
				t.Logf("server closed")
				return
			}
			panic(err)
		}
	}()
	return
}

func newWatcherClient(t *testing.T, watcherPrivateKey key.NodePrivate, serverToWatchURL string) (c *Client) {
	c, err := NewClient(watcherPrivateKey, serverToWatchURL, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	c.MeshKey = "1234"
	c.IsWatcher = true
	return
}

// Simulate a broken connection
func (c *Client) breakConnection(brokenClient *derp.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != brokenClient {
		return
	}
	if c.netConn != nil {
		c.netConn.Close()
		c.netConn = nil
	}
	c.client = nil
}

// We are testing that if the connection breaks and is re-established by
// something other than the RunWatchConnectionLoop RecvDetail(), that we still
// get peer updates.
//
// Thread 1: Server 1 serving requests. This is the watcher server.
// Thread 2: Server 2 serving requests. This is the server being watched.
// Thread 3: Watcher thread, this is a client on server 1, watching server 2, getting a peer update that itself is connected to server 2.
// Thread 4: Sending packets on the watcher connection
// Thread 5 (foreground): Breaking the connection, then waiting for the watcher thread to get the peer update, process it, and update the peer count.
//
// Our problem is: If thread 2 doesn't get a chance to run, then it can't send
// the peer update packet. If thread 3 doesn't get a chance to run, then it
// can't process the peer update packet. So we want to stop Thread 4 and 5 and 1
// and only let 3 and 4 run. Otherwise the other 3 can keep getting scheduled
// for a long time.
//
// Without this pause and wait, this turns into a halting problem.

func TestRunWatch(t *testing.T) {
	// Make the watcher server
	serverPrivateKey1 := key.NewNode()
	_, s1 := newTestServer(t, serverPrivateKey1)
	defer s1.Close()

	// Make the watched server
	serverPrivateKey2 := key.NewNode()
	serverURL2, s2 := newTestServer(t, serverPrivateKey2)
	defer s2.Close()

	// Make the watcher (but it is not connected yet)
	watcher1 := newWatcherClient(t, serverPrivateKey1, serverURL2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Make channel to wake up the connection breaking thread when the
	// watcher has run.
	ch := make(chan interface{}, 1)

	var peers atomic.Int32
	add := func(k key.NodePublic, _ netip.AddrPort) { t.Logf("add1: %v", k.ShortString()); peers.Add(1); ch <- 0 }
	remove := func(k key.NodePublic) { t.Logf("remove1: %v", k.ShortString()); peers.Add(-1) }

	// Start the watcher thread (which connects to the watched server)
	go watcher1.RunWatchConnectionLoop(ctx, serverPrivateKey1.Public(), t.Logf, add, remove)

	// Check that the watcher thread has connected the first time
	for i := 0; i < 15; i++ {
		t.Logf("peers %v", peers.Load())
		if peers.Load() >= 1 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Logf("peers %v", peers.Load())
	if peers.Load() != 1 {
		t.Fatal("wrong number of peers added during watcher connection")
	}

	// Start threads to send packets on the same connection as the watcher
	// thread, then stop and wait until watcher1 has run.
	for i := 0; i < 10; i++ {
		t.Logf("starting goroutine to send bogus Forward packets")
		go func() {
			ticker := time.Ticker(50 * time.Millisecond)
			for {
				// phase 1: send packets for a while
				// phase 2: wait till we get the signal to start again
				// repeat until we get the ctx.Done() signal
				select {
				case <-ctx.Done():
					return
				case <-ch:
					// We got the signal saying we can run
					select {
					case <-ticker.C:
						watcher1.ForwardPacket(key.NodePublic{}, key.NodePublic{}, []byte("bogus"))
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	// Now break the connection, then stop and wait for watcher1 to
	// run and check if it reconnected and sent us peer updates.
	for i := 0; i < 10; i++ {
		t.Logf("breaking connection")
		watcher1.breakConnection(watcher1.client)

		// XXX switch to our special test timer clock
		timer := time.NewTimer(5 * time.Second)

		// now wait for watcher to run
		select {
		case <-timer.C:
			// failed
		case <-ch:
			// check the number of peers
			p := peers.Load()
			if p != 1 {
				t.Fatalf("wrong number of peers added during watcher connection: %v", p)
			}
		case <-timer.C:
			// failure, watcher never ran
			t.Fatalf("watcher never ran")
		}
	}

	t.Logf("\n\n\nSHUTTING DOWN\n\n\n")
	// now cancel() should be called
}
