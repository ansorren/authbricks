package testutils

import (
	"container/list"
	"fmt"
	"net"
	"sync"
)

const (
	localhost  = "127.0.0.1"
	minTCPPort = 20000
	maxTCPPort = 60000
)

var (
	// once is used to initialise the list of available TCP ports.
	once sync.Once

	// mu guards freePorts.
	mu sync.Mutex

	// freePorts is a list of available TCP ports.
	freePorts *list.List
)

// initialisePorts loops through all TCP ports and adds them
// to the list of available ports if they're not in use.
func initialisePorts() {
	freePorts = list.New()
	for port := minTCPPort; port < maxTCPPort; port++ {
		if !isPortInUse(port) {
			freePorts.PushBack(port)
		}
	}
}

// port returns a TCP port. It is mainly used for testing purposes.
func port() int {
	mu.Lock()
	defer mu.Unlock()

	once.Do(initialisePorts)
	// take the first available port
	elem := freePorts.Front()
	freePorts.Remove(elem)
	p := elem.Value.(int)
	return p
}

// tcpAddr returns a TCP address. It is mainly used for testing purposes.
func tcpAddr(ip string, port int) *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
}

// isPortInUse returns true if the given TCP port is in use. It is mainly used for testing purposes.
func isPortInUse(port int) bool {
	ln, err := net.ListenTCP("tcp", tcpAddr("127.0.0.1", port))
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}

// unusedPort generates a random TCP Port and checks if it is in use. If it's not in use, we return it.
func unusedPort() int {
	p := port()
	if !isPortInUse(p) {
		return p
	}
	// something outside the test stole the port, try again
	fmt.Printf("port %d is in use, trying again \n", p)
	return unusedPort()
}

// LocalhostAddress returns a TCP address for localhost and a random port.
func LocalhostAddress() string {
	return tcpAddr(localhost, unusedPort()).String()
}
