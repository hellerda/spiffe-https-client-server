package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"io"
	"log"
	"math/rand"
	"net/http"
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

// Send reply after successful authentication, optionally include fortune cookie.
func serveReply(w http.ResponseWriter, r *http.Request, with_fc bool, verbose *bool) {

	if *verbose && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		log.Printf("Peer certificate chain contains %d certs.\n", len(r.TLS.PeerCertificates))
		for i, cert := range r.TLS.PeerCertificates[0:] {
			log.Printf("- Cert[%d] Subject = %s\n", i, cert.Subject)
			log.Printf("- Cert[%d] Issuer  = %s\n", i, cert.Issuer)
		}
	}

	if with_fc {
		log.Print("Client login successful: sending requested fortune cookie.\n")
		_, _ = io.WriteString(w, "Login successful!!  Server sends fortune cookie: \""+fc()+"\"\n")
	} else {
		log.Print("Client login successful.\n")
		_, _ = io.WriteString(w, "Login successful!!\n")
	}
}

type authenticator struct {
	// JWT Source used to verify token
	jwtSource *workloadapi.JWTSource
	// Expected audiences
	audiences []string
}

func (a *authenticator) authenticateClient(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// We now handle the Emissary header in addition to Authorization header.
		var token string
	loop:
		for {
			// Check for a JWT in these headers, return the first one found...
			for _, seekhdr := range []string{"Authorization", "X-Emissary-Auth"} {
				fields := strings.Fields(req.Header.Get(seekhdr))
				if len(fields) == 2 && strings.ToLower(fields[0]) == "bearer" {
					log.Printf("Connection received with JWT Bearer token from \"%s\" hdr...\n", seekhdr)
					token = fields[1]
					break loop
				}
			}
			log.Printf("Client connection received but no JWT token found.\n")
			http.Error(w, "Invalid or unsupported authorization header", http.StatusUnauthorized)
			return
		}

		// Parse and validate token against fetched bundle from jwtSource,
		// an alternative is using `workloadapi.ValidateJWTSVID` that will
		// attest against SPIRE on each call and validate token
		svid, err := jwtsvid.ParseAndValidate(token, a.jwtSource, a.audiences)
		if err != nil {
			log.Printf("Invalid token: %v\n", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		slices := strings.Split(token, ".")
		data, _ := base64.RawURLEncoding.DecodeString(slices[0])
		log.Printf("- JWT Header is %s\n", data)
		data, _ = base64.RawURLEncoding.DecodeString(slices[1])
		log.Printf("- JWT Payload is %s\n", data)

		log.Printf("Successfully verified JWT Bearer token... \n")
		log.Printf("- Audience is \"%s\"\n", svid.Claims["aud"])
		log.Printf("- Subject is \"%s\"\n", svid.Claims["sub"])

		req = req.WithContext(withSVIDClaims(req.Context(), svid.Claims))
		next.ServeHTTP(w, req)
	})
}

type svidClaimsKey struct{}

func withSVIDClaims(ctx context.Context, claims map[string]interface{}) context.Context {
	return context.WithValue(ctx, svidClaimsKey{}, claims)
}

func svidClaims(ctx context.Context) map[string]interface{} {
	claims, _ := ctx.Value(svidClaimsKey{}).(map[string]interface{})
	return claims
}

// Return a random, inspirational fortune cookie.
func fc() string {

	fortune := [...]string{
		"A friend asks only for your time not your money.",
		"If you refuse to accept anything but the best, you very often get it.",
		"A smile is your passport into the hearts of others.",
		"Your high-minded principles spell success.",
		"Hard work pays off in the future, laziness pays off now.",
		"Change can hurt, but it leads a path to something better.",
		"Enjoy the good luck a companion brings you.",
		"People are naturally attracted to you.",
		"A chance meeting opens new doors to success and friendship.",
		"What ever your goal is in life, embrace it visualize it, and for it will be yours.",
		"Land is always on the mind of a flying bird.",
		"Meeting adversity well is the source of your strength.",
		"A dream you have will come true.",
		"Our deeds determine us, as much as we determine our deeds.",
		"You will become great if you believe in yourself.",
		"There is no greater pleasure than seeing your loved ones prosper.",
		"An old flame will light up your life",
		"You already know the answer to the questions lingering inside your head.",
		"It is now, and in this world, that we must live.",
		"You must try, or never forgive yourself for not trying.",
		"You can make your own happiness.",
		"The greatest risk is not taking one.",
		"Love can last a lifetime, if you want it to.",
		"Adversity is the parent of virtue.",
		"Serious trouble will bypass you.",
		"Now is the time to try something new.",
		"Wealth awaits you very soon.",
		"If winter comes, can spring be far behind?",
		"Keep your eye out for someone special.",
		"You are very talented in many ways.",
		"A stranger is a friend you have not spoken to yet.",
		"A new voyage will fill your life with untold memories.",
		"You will travel to many exotic places in your lifetime.",
		"Your ability for accomplishment will follow with success.",
		"When fear hurts you, conquer it and defeat it!",
		"The man on the top of the mountain did not fall there.",
		"You will conquer obstacles to achieve success.",
		"Fortune favors the brave.",
		"A journey of a thousand miles begins with a single step.",
		"Stay true to those who would do the same for you.",
		"Integrity is the essence of everything successful.",
		"You will always be surrounded by true friends",
		"Your golden opportunity is coming shortly.",
		"For hate is never conquered by hate. Hate is conquered by love .",
		"You will make many changes before settling down happily.",
		"You cannot become rich except by enriching others.",
		"You can open doors with your charm and patience.",
		"He who expects nothing shall never be disappointed.",
	}

	rand.Seed(time.Now().UnixNano())
	return fortune[rand.Intn(len(fortune))]
}

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
		audience       = flag.String("audience", "CI", "The audience we expect to receive in the caller's JWT claim")
		clientSpiffeID = flag.String("mTLS", "", "If set, verify the client cert against the provided Spiffe ID")
		listenPort     = flag.String("listenPort", "", "TCP port for the server to listen on (default \"80\" for HTTP, \"443\" for HTTPS)")
		noTLS          = flag.Bool("noTLS", false, "Run as a simple HTTP server, no HTTPS")
		noJWT          = flag.Bool("noJWT", false, "Skip verifying JWT from the client")
		socketPath     = flag.String("socketPath", "", "Path to the SPIRE Agent API socket (default: \"/tmp/spire-agent/public/api.sock\")")
		socketAddr     = flag.String("socketAddr", "", "TCP address to connect to the SPIRE Agent API, in the form of \"IP:PORT\"")
		verbose        = flag.Bool("v", false, "Show more details (verbose)")
	)
	flag.Parse()

	if *socketPath != "" && *socketAddr != "" {
		log.Fatalf("Conflicting options: -socketPath and -socketAddr")
	}

	default_port_http := 80
	default_port_https := 443

	ctx := context.Background()

	// Create client options to specify the expected SPIRE Agent socket path...
	clientOptions, _ := getSpiffeSourceOption(*socketPath, *socketAddr)

	var server *http.Server
	if !*noTLS {
		// Create a X509Source using the previously created workloadapi client...
		x509Source, err := workloadapi.NewX509Source(ctx, clientOptions)
		if err != nil {
			log.Fatalf("Unable to create X509Source: %v", err)
		}
		defer x509Source.Close()

		// Create a `tls.Config` to manage communication with other SPIFFE endpoints, supporting TLS or mTLS as we need...
		var tlsConfig *tls.Config
		if *clientSpiffeID == "" {
			tlsConfig = tlsconfig.TLSServerConfig(x509Source)
		} else {
			clientID := spiffeid.RequireFromString(*clientSpiffeID)
			tlsConfig = tlsconfig.MTLSServerConfig(x509Source, x509Source, tlsconfig.AuthorizeID(clientID))
		}

		log.Printf("Successfully retrieved TLS ServerConfig with ServerName \"%s\"...\n", tlsConfig.ServerName)
		for i, cert := range tlsConfig.Certificates[0:] {
			log.Printf("- Cert[%d] Subject = %s\n", i, cert.Leaf.Subject)
			log.Printf("- Cert[%d] Issuer = %s\n", i, cert.Leaf.Issuer)
		}

		if *listenPort == "" {
			*listenPort = strconv.Itoa(default_port_https)
		}

		// Create a simple https Server using this 'tlsConfig'...
		server = &http.Server{
			Addr:      (":" + *listenPort),
			TLSConfig: tlsConfig,
		}
	}

	if !*noJWT {
		// Create a JWTSource to validate incoming tokens from clients...
		jwtSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
		if err != nil {
			log.Fatalf("Unable to create JWTSource: %v", err)
		}
		defer jwtSource.Close()

		// Add a middleware function to validate presented JWT token (which is simply our "authenticator" function)
		auth := &authenticator{
			jwtSource: jwtSource,
			audiences: []string{(*audience)},
			// audiences: []string{"spiffe://example.org/server-workload"},
		}
		http.Handle("/", auth.authenticateClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveReply(w, r, false, verbose) })))
		http.Handle("/fortune", auth.authenticateClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveReply(w, r, true, verbose) })))
	} else {
		http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveReply(w, r, false, verbose) }))
		http.Handle("/fortune", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveReply(w, r, true, verbose) }))
	}

	// Start the server running as requested.
	if *noTLS {
		if *listenPort == "" {
			*listenPort = strconv.Itoa(default_port_http)
		}
		log.Fatal(http.ListenAndServe(":"+(*listenPort), nil))
	} else {
		log.Fatal(server.ListenAndServeTLS("", ""))
	}
}
