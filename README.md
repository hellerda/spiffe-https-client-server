# Overview

```spiffe-https-client-server``` is a simple HTTP/S client/server application you can use to test SPIRE-backed TLS and mTLS communication between endpoints.  It handles JWT authentication as well, fetching a JWT SVID from one side of the connection and validating it on the other.  The HTTP/S function works by retrieving a ```tlsconfig``` object from the SPIRE Workload API, consumed directly the Golang ```net/http``` package.  The JWT SVID fetch and validation operations are handled by the client and server programs, performing the operations directly through the SPIRE Workload API.  The project builds two binaries, ```https-client``` and ```https-server```.

Based on the SPIFFE [go-spiffe (v2) Examples](https://github.com/spiffe/go-spiffe/tree/main/v2/examples).


# Functionality

For HTTPS, the client and server programs can support either TLS or mTLS communication as specified by command line options.  They can also be operated in simple HTTP mode, which is useful for basic connection testing or when one or both endpoints sits behind a proxy.  In HTTP mode, the client can direct outbound traffic through a forward HTTP proxy, accepting the address of a (commonly, but not necessarily) local HTTP proxy interface by command-line option.  In HTTPS mode, the SPIRE-issued ```tlsconfig``` object handles x509 SVID and trust bundle rotation automatically.  This allows the HTTPS server to run continuously, regardless of the lifetime of the SVIDs themselves.

For JWT authentication, the client program accepts, via command-line option, the "audience" to be added to the JWT claim.  Server-side, the ```https-server``` program allows the user to specify the expected audience for the incoming JWT.  The server looks for the JWT in the incoming "Authorization" (or "X-Emissary-Auth") HTTP header.  If the audience claim matches, and the JWT is otherwise successfully validated by the SPIRE Workload API, the incoming connection is authorized.

The JWT authentication operates independently of the TLS authentication, allowing them to be used separately.  This is useful, say, when passing through a proxy that handles one function but not the other.  For example, you could have a proxy that handles mTLS authentication but not JWT; in this case you would run in HTTP mode but specify your own JWT creation and validation at client and server, allowing the program to handle JWT authentication while the proxy handles TLS.

The ```https-client``` and ```https-server``` programs handle TLS and JTW authentication independently of each, as well.  This is useful, say, when one endpoint sits behind a SPIRE enabled proxy and the other does not.

The program performs no real function other than to display "Login successful!" at the client when the proper conditions are met.  It also displays details of the TLS or JWT authentication at both endpoints.  To make it a bit more fun, the server will return an inspirational quote or "fortune cookie" when the ```/fortune``` HTTP endpoint is accessed, e.g. by specifying the ```-fc``` option to ```https-client```.

Note that as a simple HTTP/S client/server program, ```spiffe-https-client-server``` is interoperable with other HTTP/S programs like ```wget``` or ```curl```.  You will have to handle any TLS operation on your own, e.g. by fetching an x509 SVID from SPIRE and specifying the correct ```wget``` or ```curl``` cmdline options to pass it.


# Usage
```
$ https-server -help
Usage of https-server:
  -audience string
        The audience we expect to receive in the caller's JWT claim (default "CI")
  -listenPort string
        TCP port for the server to listen on (default "80" for HTTP, "443" for HTTPS)
  -mTLS string
        If set, verify the client cert against the provided Spiffe ID
  -noJWT
        Skip verifying JWT from the client
  -noTLS
        Run as a simple HTTP server, no HTTPS
  -socketAddr string
        TCP address to connect to the SPIRE Agent API, in the form of "IP:PORT"
  -socketPath string
        Path to the SPIRE Agent API socket (default: "/tmp/spire-agent/public/api.sock")
  -v    Show more details (verbose)
```

```
$ https-client --help
Usage of https-client:
  -audience string
        The audience we send in JWT claims
  -fc
        Request fortune cooke from server
  -host string
        IP or DNS name of remote host (default "localhost")
  -mTLS
        Send client certificate to server (perform mTLS)
  -noJWT
        Skip sending a JWT to the server
  -noTLS
        Run as a simple HTTP client, no HTTPS
  -peerSpiffeID string
        The expected SpiffeID of the remote host (default "spiffe://example.com/https-server")
  -port string
        TCP port to connect to at the remote host (default "80" for HTTP, "443" for HTTPS)
  -proxyURL string
        Use outbound proxy for TLS connection
  -socketPath string
        Path to the SPIRE Agent API socket (default "/tmp/spire-agent/public/api.sock")
  -v    Show more details (verbose)
```


# Build

To build both binaries:
```
make
```

### Other build options
```
make stripped
make static
make static-and-stripped
```

### Build binaries separately
```
make https-client
make https-server

make https-client-stripped
make https-server-stripped

make https-client-static
make https-server-static

make https-client-static-and-stripped
make https-server-static-and-stripped
```

### Remove both binaries
```
make clean
```


# Examples

## https-server

**Example:** To start an HTTPS server running on the with mTLS and JWT authentication, with the expected Spiffe ID of the remote endpoint specified by ```-mTLS```, and an expected audience claim of the incoming JWT specified by ```-audience```:
```
$ https-server -audience "myapp" -mTLS "spiffe://example.org/ns/spire/sa/myworkload"
```
NOTE: the ```-audience``` is an arbitrary string that must simply match between client and server.  There is no requirement in the program (or in SPIRE itself) for the audience to match the endpoint's trust domain or Spiffe ID, although some software, like [Emissary](https://github.com/github/emissary), may enforce additional requirements on the audience.

**Example:** To start an HTTPS server listening on port 2222, with mTLS authentication but no JWT, with the expected Spiffe ID of the remote endpoint specified by ```-mTLS```:
```
$ https-server -listenPort 2222 -noJWT -mTLS "spiffe://example.org/ns/spire/sa/myworkload"
```

**Example:** To start a simple HTTP server with no TLS and requiring no JWT authentication:
```
$ https-server -listenPort 2222 -noJWT -noTLS
```

## https-client

**Example:** To use the client to connect to an HTTPS server requiring mTLS and JWT authentication, over port 2222, requiring the JWT claim specified by ```-audience```, with an expected server Spiffe ID specified by ```-peerSpiffeID```:
```
$ https-client -host api.myapp.example.org -port 2222 -audience "api.myapp" -peerSpiffeID "spiffe://example.org/myapp-server" -mTLS
```

**Example:** To connect to an HTTP server with no TLS but requiring JWT authentication, with the required JWT claim specified by ```-audience```, requesting a fortune cookie on successful authentication:
```
$ https-client -host 192.168.0.50 -port 2222 -audience "api.myapp" -noTLS -fc
```

**Example:** To connect to a server at the address specified by ```-host``` on port 2222, via a local HTTP proxy listening on port 2223:
```
$ https-client -proxyURL http://localhost:2223 -host 192.168.0.50 -port 2222 -noJWT -noTLS
```
In the above example, the client connects to the proxy over HTTP; if the server requires a TLS connection or JWT authentication, it is up to the proxy to handle.


# Accessing the SPIRE Agent socket

The workload typically accesses the SPIRE Agent socket over a Unix domain socket (UDS).  The default path is ```/tmp/spire-agent/public/api.sock```.  To access the socket over a different path:
```
$ https-client -socketPath /run/spire/sockets/agent.sock ...
```
where ```...``` represents the remainder of the command line.

In cases where the UDS cannot be made directly available to the workload (e.g. to a container in a different process namespace), the workload can alternately access the SPIRE Agent over a TCP socket, using the ```-socketAddr``` option to access the address.  The address is of the form "IP:PORT", where the IP is optional and defaults to "127.0.0.1", and the PORT is required (no default).  The following forms are valid:

```
$ https-client -socketAddr 127.0.0.1:1234 ...
$ https-client -socketAddr :1234 ...
```

If this option is specified it overrides the ```-socketPath``` option.

The SPIRE Agent is not able to host a TCP port directly; to do this you must front the UDS with a TCP proxy:  To use an SSH tunnel:
```
$ ssh -R 1234:/tmp/spire-agent/public/api.sock user@localhost
```

To use ```socat```:
```
$ socat TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8 UNIX-CLIENT:/tmp/spire-agent/public/api.sock
```
Note this method does not perform true workload attestation; the attested process will always be the local proxy, not the end workload.  This should only be done on an isolated network where the intended workload will be the only process able to access the agent TCP port.

The ```-socketPath``` and ```-socketPath``` options work similarly for ```http-server``` as well.
