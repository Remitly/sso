package devproxy

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/18F/hmacauth"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
)

// HMACSignatureHeader is the header name where the signed request header is stored.
const HMACSignatureHeader = "Gap-Signature"

// SignatureHeaders are the headers that are valid in the request.
var SignatureHeaders = []string{
	"X-Forwarded-User",
	"X-Forwarded-Email",
	"X-Forwarded-Groups",
	"X-Forwarded-Access-Token",
}

const statusInvalidHost = 421

// DevProxy stores all the information associated with proxying the request.
type DevProxy struct {
	// redirectURL       *url.URL // the url to receive requests at
	skipAuthPreflight bool
	templates         *template.Template
	mux               map[string]*route
	regexRoutes       []*route
	requestSigner     *RequestSigner
	publicCertsJSON   []byte
}

type route struct {
	upstreamConfig *UpstreamConfig
	handler        http.Handler
	tags           []string

	// only used for ones that have regex
	regex *regexp.Regexp
}

// StateParameter holds the redirect id along with the session id.
type StateParameter struct {
	SessionID   string `json:"session_id"`
	RedirectURI string `json:"redirect_uri"`
}

// UpstreamProxy stores information necessary for proxying the request back to the upstream.
type UpstreamProxy struct {
	name          string
	handler       http.Handler
	requestSigner *RequestSigner
}

// upstreamTransport is used to ensure that upstreams cannot override the
// security headers applied by dev_proxy
type upstreamTransport struct {
	transport *http.Transport
}

// RoundTrip round trips the request and deletes security headers before returning the response.
func (t *upstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		logger := log.NewLogEntry()
		logger.Error(err, "error in upstreamTransport RoundTrip")
		return nil, err
	}
	for key := range securityHeaders {
		resp.Header.Del(key)
	}
	return resp, err
}

func newUpstreamTransport(insecureSkipVerify bool) *upstreamTransport {
	return &upstreamTransport{
		transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecureSkipVerify},
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// ServeHTTP calls the upstream's ServeHTTP function.
func (u *UpstreamProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if u.requestSigner != nil {

		u.requestSigner.Sign(r)
	}

	start := time.Now()
	u.handler.ServeHTTP(w, r)
	duration := time.Now().Sub(start)

	fmt.Printf("service_name:%s, duration:%s", u.name, duration)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// NewReverseProxy creates a reverse proxy to a specified url.
// It adds an X-Forwarded-Host header that is the request's host.
func NewReverseProxy(to *url.URL, config *UpstreamConfig) *httputil.ReverseProxy {
	targetQuery := to.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = to.Scheme
		req.URL.Host = to.Host
		req.URL.Path = singleJoiningSlash(to.Path, req.URL.Path)

		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}
	proxy := &httputil.ReverseProxy{Director: director}
	proxy.Transport = newUpstreamTransport(config.TLSSkipVerify)
	dir := proxy.Director

	proxy.Director = func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		dir(req)
		req.Host = to.Host
	}
	return proxy
}

// NewRewriteReverseProxy creates a reverse proxy that is capable of creating upstream
// urls on the fly based on a from regex and a templated to field.
// It adds an X-Forwarded-Host header to the the upstream's request.
func NewRewriteReverseProxy(route *RewriteRoute, config *UpstreamConfig) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{}
	proxy.Transport = newUpstreamTransport(config.TLSSkipVerify)
	proxy.Director = func(req *http.Request) {
		// we do this to rewrite requests
		rewritten := route.FromRegex.ReplaceAllString(req.Host, route.ToTemplate.Opaque)

		// we use to favor scheme's used in the regex, else we use the default passed in via the template
		target, err := urlParse(route.ToTemplate.Scheme, rewritten)
		if err != nil {
			logger := log.NewLogEntry()
			// we aren't in an error handling context so we have to fake it(thanks stdlib!)
			logger.WithRequestHost(req.Host).WithRewriteRoute(route).Error(
				err, "unable to parse and replace rewrite url")
			req.URL = nil // this will raise an error in http.RoundTripper
			return
		}
		director := httputil.NewSingleHostReverseProxy(target).Director

		req.Header.Add("X-Forwarded-Host", req.Host)
		director(req)
		req.Host = target.Host
	}
	return proxy
}

// NewReverseProxyHandler creates a new http.Handler given a httputil.ReverseProxy
func NewReverseProxyHandler(reverseProxy *httputil.ReverseProxy, opts *Options, config *UpstreamConfig, signer *RequestSigner) (http.Handler, []string) {
	upstreamProxy := &UpstreamProxy{
		name:          config.Service,
		handler:       reverseProxy,
		requestSigner: signer,
	}

	if config.SkipRequestSigning {
		upstreamProxy.requestSigner = nil
	}

	if config.FlushInterval != 0 {
		return NewStreamingHandler(upstreamProxy, opts, config), []string{"handler:streaming"}
	}
	return NewTimeoutHandler(upstreamProxy, opts, config), []string{"handler:timeout"}
}

// NewTimeoutHandler creates a new handler with a configure timeout.
func NewTimeoutHandler(handler http.Handler, opts *Options, config *UpstreamConfig) http.Handler {
	timeout := opts.DefaultUpstreamTimeout
	if config.Timeout != 0 {
		timeout = config.Timeout
	}
	timeoutMsg := fmt.Sprintf(
		"%s failed to respond within the %s timeout period", config.Service, timeout)
	return http.TimeoutHandler(handler, timeout, timeoutMsg)
}

// NewStreamingHandler creates a new handler capable of proxying a stream
func NewStreamingHandler(handler http.Handler, opts *Options, config *UpstreamConfig) http.Handler {
	upstreamProxy := handler.(*UpstreamProxy)
	reverseProxy := upstreamProxy.handler.(*httputil.ReverseProxy)
	reverseProxy.FlushInterval = config.FlushInterval
	return upstreamProxy
}

func generateHmacAuth(signatureKey string) (hmacauth.HmacAuth, error) {
	components := strings.Split(signatureKey, ":")
	if len(components) != 2 {
		return nil, fmt.Errorf("invalid signature hash:key spec")
	}

	algorithm, secret := components[0], components[1]
	hash, err := hmacauth.DigestNameToCryptoHash(algorithm)
	if err != nil {
		return nil, fmt.Errorf("unsupported signature hash algorithm: %s", algorithm)
	}
	auth := hmacauth.NewHmacAuth(hash, []byte(secret), HMACSignatureHeader, SignatureHeaders)
	return auth, nil
}

// NewDevProxy creates a new DevProxy struct.
func NewDevProxy(opts *Options, optFuncs ...func(*DevProxy) error) (*DevProxy, error) {
	logger := log.NewLogEntry()
	logger.Info("NewDevProxy...")

	// Configure the RequestSigner (used to sign requests with `Sso-Signature` header).
	// Also build the `certs` static JSON-string which will be served from a public endpoint.
	// The key published at this endpoint allows upstreams to decrypt the `Sso-Signature`
	// header, and validate the integrity and authenticity of a request.

	certs := make(map[string]string)
	var requestSigner *RequestSigner
	var err error
	if len(opts.RequestSigningKey) > 0 {
		requestSigner, err = NewRequestSigner(opts.RequestSigningKey)

		if err != nil {
			return nil, fmt.Errorf("could not build RequestSigner: %s", err)
		}
		id, key := requestSigner.PublicKey()
		certs[id] = key

	} else {
		logger.Warn("Running DevProxy without signing key. Requests will not be signed.")
	}

	certsAsStr, err := json.MarshalIndent(certs, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("could not marshal public certs as JSON: %s", err)
	}

	p := &DevProxy{
		// these fields make up the routing mechanism
		mux:         make(map[string]*route),
		regexRoutes: make([]*route, 0),

		// redirectURL:     &url.URL{Path: "/oauth2/callback"},
		templates:       getTemplates(),
		requestSigner:   requestSigner,
		publicCertsJSON: certsAsStr,
	}

	for _, optFunc := range optFuncs {
		err := optFunc(p)
		if err != nil {
			return nil, err
		}
	}

	for _, upstreamConfig := range opts.upstreamConfigs {
		switch route := upstreamConfig.Route.(type) {
		case *SimpleRoute:
			reverseProxy := NewReverseProxy(route.ToURL, upstreamConfig)
			handler, tags := NewReverseProxyHandler(reverseProxy, opts, upstreamConfig, requestSigner)
			p.Handle(route.FromURL.Host, handler, tags, upstreamConfig)
		case *RewriteRoute:
			reverseProxy := NewRewriteReverseProxy(route, upstreamConfig)
			handler, tags := NewReverseProxyHandler(reverseProxy, opts, upstreamConfig, requestSigner)
			p.HandleRegex(route.FromRegex, handler, tags, upstreamConfig)
		default:
			return nil, fmt.Errorf("unknown route type")
		}
	}

	return p, nil
}

// Handler returns a http handler for an DevProxy
func (p *DevProxy) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/favicon.ico", p.Favicon)
	mux.HandleFunc("/robots.txt", p.RobotsTxt)
	mux.HandleFunc("/oauth2/v1/certs", p.Certs)
	mux.HandleFunc("/", p.Proxy)

	// Global middleware, which will be applied to each request in reverse
	// order as applied here (i.e., we want to validate the host _first_ when
	// processing a request)
	var handler http.Handler = mux
	handler = p.setResponseHeaderOverrides(handler)
	handler = setSecurityHeaders(handler)
	handler = p.validateHost(handler)

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Skip host validation for /ping requests because they hit the LB directly.
		if req.URL.Path == "/ping" {
			p.PingPage(rw, req)
			return
		}
		handler.ServeHTTP(rw, req)
	})
}

// RobotsTxt sets the User-Agent header in the response to be "Disallow"
func (p *DevProxy) RobotsTxt(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "User-agent: *\nDisallow: /")
}

// Favicon will proxy the request as usual
func (p *DevProxy) Favicon(rw http.ResponseWriter, req *http.Request) {
	err := p.setProxyHeaders(rw, req)
	if err != nil {
		rw.WriteHeader(http.StatusNotFound)
		return
	}
	rw.WriteHeader(http.StatusOK)
	p.Proxy(rw, req)
}

// PingPage send back a 200 OK response.
func (p *DevProxy) PingPage(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "OK")
}

// ErrorPage renders an error page with a given status code, title, and message.
func (p *DevProxy) ErrorPage(rw http.ResponseWriter, req *http.Request, code int, title string, message string) {
	if p.isXMLHTTPRequest(req) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(code)
		err := json.NewEncoder(rw).Encode(struct {
			Error string `json:"error"`
		}{
			Error: message,
		})
		if err != nil {
			io.WriteString(rw, err.Error())
		}
	} else {
		logger := log.NewLogEntry()
		logger.WithHTTPStatus(code).WithPageTitle(title).WithPageMessage(message).Info(
			"error page")
		rw.WriteHeader(code)
		t := struct {
			Code    int
			Title   string
			Message string
		}{
			Code:    code,
			Title:   title,
			Message: message,
		}
		p.templates.ExecuteTemplate(rw, "error.html", t)
	}
}

func (p *DevProxy) isXMLHTTPRequest(req *http.Request) bool {
	return req.Header.Get("X-Requested-With") == "XMLHttpRequest"
}

// Proxy forwards the request.
func (p *DevProxy) Proxy(rw http.ResponseWriter, req *http.Request) {

	logger := log.NewLogEntry()
	p.setProxyHeaders(rw, req)

	logger.Info("Proxy...")
	// We now proxy their request to the provided upstream.
	route, ok := p.router(req)
	if !ok {
		p.UnknownHost(rw, req)
		return
	}

	route.handler.ServeHTTP(rw, req)
}

// UnknownHost returns an http error for unknown or invalid hosts
func (p *DevProxy) UnknownHost(rw http.ResponseWriter, req *http.Request) {
	logger := log.NewLogEntry()

	logger.WithRequestHost(req.Host).Error("unknown host")
	http.Error(rw, "", statusInvalidHost)
}

// Handle constructs a route from the given host string and matches it to the provided http.Handler and UpstreamConfig
func (p *DevProxy) Handle(host string, handler http.Handler, tags []string, upstreamConfig *UpstreamConfig) {
	tags = append(tags, "route:simple")
	p.mux[host] = &route{handler: handler, upstreamConfig: upstreamConfig, tags: tags}
}

// HandleRegex constructs a route from the given regexp and matches it to the provided http.Handler and UpstreamConfig
func (p *DevProxy) HandleRegex(regex *regexp.Regexp, handler http.Handler, tags []string, upstreamConfig *UpstreamConfig) {
	tags = append(tags, "route:rewrite")
	p.regexRoutes = append(p.regexRoutes, &route{regex: regex, handler: handler, upstreamConfig: upstreamConfig, tags: tags})
}

func (p *DevProxy) setProxyHeaders(rw http.ResponseWriter, req *http.Request) (err error) {
	req.Header.Set("X-Forwarded-User", req.Header.Get("User"))
	req.Header.Set("X-Forwarded-Email", req.Header.Get("Email"))
	req.Header.Set("X-Forwarded-Groups", req.Header.Get("groups"))
	// req.Header.set("X-Forwarded-Access-Token", "")
	return nil
}

// router attempts to find a route for a request. If a route is successfully matched,
// it returns the route information and a bool value of `true`. If a route can not be matched,
//a nil value for the route and false bool value is returned.
func (p *DevProxy) router(req *http.Request) (*route, bool) {
	route, ok := p.mux[req.Host]
	if ok {
		return route, true
	}

	for _, route := range p.regexRoutes {
		if route.regex.MatchString(req.Host) {
			return route, true
		}
	}

	return nil, false
}

// Certs publishes the public key necessary for upstream services to validate the digital signature
// used to sign each request.
func (p *DevProxy) Certs(rw http.ResponseWriter, _ *http.Request) {
	rw.Write(p.publicCertsJSON)
}
