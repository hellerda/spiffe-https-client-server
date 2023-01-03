package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	defaultSocketPath = "/tmp/spire-agent/public/api.sock"
)

// Call the SPIRE Workload API over UDS or TCP socket...
func getSpiffeSourceOption(socketPath string, socketAddr string) (workloadapi.SourceOption, error) {

	var socket_addr string

	if socketAddr != "" {

		slices := strings.Split(socketAddr, ":")
		if len(slices) != 2 {
			log.Fatalf("socketAddr must be in the form of IP:PORT or :PORT")
		}
		if slices[1] == "" {
			log.Fatalf("socketAddr must contain port value, in the form of IP:PORT or :PORT")
		}
		if slices[0] == "" {
			slices[0] = "127.0.0.1"
		}
		socket_addr = "tcp://" + slices[0] + ":" + slices[1]

	} else if socketPath != "" {
		socket_addr = "unix://" + socketPath

	} else {
		socket_addr = "unix://" + defaultSocketPath
	}

	return workloadapi.WithClientOptions(workloadapi.WithAddr(socket_addr)), nil
}

func main() {

	// Command line options...
	var (
		aud          = flag.String("audience", "", "The audience we send in JWT claims")
		fc           = flag.Bool("fc", false, "Request fortune cooke from server")
		hostname     = flag.String("host", "localhost", "IP or DNS name of remote host")
		hostport     = flag.String("port", "", "TCP port to connect to at the remote host (default \"80\" for HTTP, \"443\" for HTTPS)")
		mTLS         = flag.Bool("mTLS", false, "Send client certificate to server (perform mTLS)")
		noTLS        = flag.Bool("noTLS", false, "Run as a simple HTTP client, no HTTPS")
		noJWT        = flag.Bool("noJWT", false, "Skip sending a JWT to the server")
		peerSpiffeID = flag.String("peerSpiffeID", "spiffe://example.com/https-server", "The expected SpiffeID of the remote host")
		socketPath   = flag.String("socketPath", "", "Path to the SPIRE Agent API socket (default: \"/tmp/spire-agent/public/api.sock\")")
		socketAddr   = flag.String("socketAddr", "", "TCP address to connect to the SPIRE Agent API, in the form of \"IP:PORT\"")
		proxy        = flag.String("proxyURL", "", "Use outbound proxy for TLS connection")
		verbose      = flag.Bool("v", false, "Show more details (verbose)")
	)
	flag.Parse()

	if *mTLS && *noTLS {
		log.Fatalf("Conflicting options: -mTLS and -noTLS")
	}

	if *socketPath != "" && *socketAddr != "" {
		log.Fatalf("Conflicting options: -socketPath and -socketAddr")
	}

	default_port_http := 80
	default_port_https := 443

	var serverURL string
	if *noTLS {
		if *hostport == "" {
			*hostport = strconv.Itoa(default_port_http)
		}
		serverURL = "http://" + *hostname + ":" + *hostport
	} else {
		if *hostport == "" {
			*hostport = strconv.Itoa(default_port_https)
		}
		serverURL = "https://" + *hostname + ":" + *hostport
	}

	// Time out trying to access the SPIRE Agent socket...
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Create client options to specify the expected SPIRE Agent socket path...
	clientOptions, _ := getSpiffeSourceOption(*socketPath, *socketAddr)

	var client http.Client
	var serverSpiffeID spiffeid.ID

	if !*noTLS {
		serverSpiffeID, _ = spiffeid.FromString(*peerSpiffeID)
		log.Printf("The server SPIFFE ID we're expecting is \"%s\"\n", serverSpiffeID.String())

		// Create a X509Source using the previously created workloadapi client...
		x509Source, err := workloadapi.NewX509Source(ctx, clientOptions)
		if err != nil {
			log.Fatalf("Unable to create X509Source: %v", err)
		}
		defer x509Source.Close()

		// Create a `tls.Config` to manage communication with other SPIFFE endpoints, supporting TLS or mTLS as we need...
		var tlsConfig *tls.Config
		if !*mTLS {
			log.Printf("Requesting a 'tlsconfig' to verify server cert and ensure \"%s\" in the Subject or SANS...\n", serverSpiffeID.String())
			tlsConfig = tlsconfig.TLSClientConfig(x509Source, tlsconfig.AuthorizeID(serverSpiffeID))
		} else {
			log.Printf("Requesting an mTLS 'tlsconfig' to verify server cert and ensure \"%s\" in the Subject or SANS...\n", serverSpiffeID.String())
			tlsConfig = tlsconfig.MTLSClientConfig(x509Source, x509Source, tlsconfig.AuthorizeID(serverSpiffeID))
		}

		if *verbose && tlsConfig.Certificates != nil && len(tlsConfig.Certificates) > 0 {
			log.Printf("The 'tlsConfig' contains %d Certificates.\n", len(tlsConfig.Certificates))
			for i, cert := range tlsConfig.Certificates[0:] {
				log.Printf("- Cert[%d] Subject = %s\n", i, cert.Leaf.Subject)
				log.Printf("- Cert[%d] Issuer = %s\n", i, cert.Leaf.Issuer)
			}
			if tlsConfig.RootCAs == nil {
				log.Printf("- No tlsConfig.RootCAs set.\n")
			}
			if tlsConfig.ClientCAs == nil {
				log.Printf("- No tlsConfig.ClientCAs set.\n")
			}
		}

		// Create a simple https Client with this 'tlsConfig'...
		client = http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	} else {
		// Create a simple Transport with HTTP Proxy...
		if *proxy != "" {
			proxyURL, err := url.Parse(*proxy)
			if err != nil {
				log.Fatalf("Cannot parse proxy URL: %s", *proxy)
			}
			transport := http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: nil,
			}
			client = http.Client{
				Transport: &transport,
			}
		} else {
			client = http.Client{}
		}
	}

	var req *http.Request
	var err error
	if *fc {
		req, err = http.NewRequest("GET", serverURL+"/fortune", nil)
		if err != nil {
			log.Fatalf("Unable to create request: %v", err)
		}
	} else {
		req, err = http.NewRequest("GET", serverURL, nil)
		if err != nil {
			log.Fatalf("Unable to create request: %v", err)
		}
	}

	if !*noJWT {
		audience := serverSpiffeID.String()
		if len(*aud) > 0 {
			audience = *aud
		}

		// Create a JWTSource to fetch SVIDs
		jwtSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
		if err != nil {
			log.Fatalf("Unable to create JWTSource: %v", err)
		}
		defer jwtSource.Close()

		// Fetch JWT SVID and attach it to the appropriate HTTP header(s)...
		svid, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{
			Audience: audience,
		})
		if err != nil {
			log.Fatalf("Unable to fetch SVID: %v", err)
		}
		log.Printf("Successfully fetched JWT SVID... this is what we will send...\n")

		slices := strings.Split(svid.Marshal(), ".")
		data, _ := base64.RawURLEncoding.DecodeString(slices[0])
		log.Printf("- JWT Header is %s\n", data)
		data, _ = base64.RawURLEncoding.DecodeString(slices[1])
		log.Printf("- JWT Payload is %s\n", data)

		if *verbose {
			log.Printf("- Audience is \"%s\"\n", svid.Claims["aud"])
			log.Printf("- Subject is \"%s\"\n", svid.Claims["sub"])
		}

		// We now handle the Emissary header in addition to Authorization header.
		log.Printf("Setting Authorization header with JWT Bearer token... \n")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", svid.Marshal()))
		// Emissary requires this header specifically, it's hard-coded in Emissary src.
		// And it's case-sensitive, here is how to set it directly...
		req.Header["x-emissary-auth"] = []string{"bearer " + svid.Marshal()}
	}

	log.Printf("Attempting to connect to the server on port %s... \n", *hostport)
	res, err := client.Do(req)
	if err != nil {
		log.Fatalf("Unable to connect to %q: %v", serverURL, err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	if *verbose && res.TLS != nil && len(res.TLS.PeerCertificates) > 0 {
		log.Printf("Peer certificate chain contains %d certs.\n", len(res.TLS.PeerCertificates))
		for i, cert := range res.TLS.PeerCertificates[0:] {
			log.Printf("- Cert[%d] Subject = %s\n", i, cert.Subject)
			log.Printf("- Cert[%d] Issuer  = %s\n", i, cert.Issuer)
		}
	}

	log.Printf("%s", body)
}
