package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/byte-v-forge/proxy-runtime/internal/provider/ten24"
)

const (
	ProviderTen24  = "1024proxy"
	ProviderNone   = "none"
	ProviderStatic = "static"
)

var ErrUnsupportedProvider = errors.New("unsupported proxy provider")

const (
	ListenerRouteDirect   = "direct"
	ListenerRouteProvider = "provider"
	ListenerRouteUpstream = "upstream"
)

type EgressListener struct {
	ID       string            `json:"id"`
	Addr     string            `json:"addr"`
	Protocol string            `json:"protocol"`
	Route    string            `json:"route"`
	Upstream string            `json:"upstream"`
	Username string            `json:"username"`
	Password string            `json:"password"`
	Labels   map[string]string `json:"labels"`
}

type Config struct {
	RuntimeAddr       string
	GostPath          string
	GostConfigDir     string
	GostAPIAddr       string
	GostMetricsAddr   string
	ProviderTargets   []string
	CommonEgressAddr  string
	LocalAddr         string
	LocalProtocol     string
	LocalUsername     string
	LocalPassword     string
	StaticChain       []string
	SimpleProxies     []string
	ProviderHTTPProxy string
	Provider          string
	Listeners         []EgressListener
	RefreshInterval   time.Duration
	RequestTimeout    time.Duration
	IPRiskCheck       IPRiskCheck
	Ten24             ten24.Config
}

type IPRiskCheck struct {
	Enabled       bool
	URL           string
	DiscoverURLs  []string
	MaxAttempts   int
	Timeout       time.Duration
	MinTrustScore int
}

func LoadFromEnv() (Config, error) {
	cfg := Config{
		RuntimeAddr:       envDefault("PROXY_RUNTIME_ADDR", ":8080"),
		GostPath:          envDefault("PROXY_RUNTIME_GOST_PATH", "gost"),
		GostConfigDir:     strings.TrimSpace(os.Getenv("PROXY_RUNTIME_GOST_CONFIG_DIR")),
		GostAPIAddr:       strings.TrimSpace(os.Getenv("PROXY_RUNTIME_GOST_API_ADDR")),
		GostMetricsAddr:   strings.TrimSpace(os.Getenv("PROXY_RUNTIME_GOST_METRICS_ADDR")),
		ProviderTargets:   envList("PROXY_RUNTIME_PROVIDER_TARGETS"),
		CommonEgressAddr:  strings.TrimSpace(os.Getenv("PROXY_RUNTIME_COMMON_EGRESS_ADDR")),
		LocalAddr:         envDefault("PROXY_RUNTIME_DYNAMIC_EGRESS_ADDR", envDefault("PROXY_RUNTIME_LOCAL_ADDR", ":1080")),
		LocalProtocol:     envDefault("PROXY_RUNTIME_LOCAL_PROTOCOL", "http"),
		LocalUsername:     strings.TrimSpace(os.Getenv("PROXY_RUNTIME_LOCAL_USERNAME")),
		LocalPassword:     strings.TrimSpace(os.Getenv("PROXY_RUNTIME_LOCAL_PASSWORD")),
		StaticChain:       envList("PROXY_RUNTIME_STATIC_CHAIN"),
		SimpleProxies:     envList("PROXY_RUNTIME_SIMPLE_PROXIES"),
		ProviderHTTPProxy: strings.TrimSpace(os.Getenv("PROXY_RUNTIME_PROVIDER_HTTP_PROXY")),
		Provider:          envDefault("PROXY_RUNTIME_PROVIDER", ProviderTen24),
		Listeners:         envListeners("PROXY_RUNTIME_LISTENERS_JSON"),
		RefreshInterval:   envDurationSeconds("PROXY_RUNTIME_REFRESH_SECONDS", 300*time.Second),
		RequestTimeout:    envDurationSeconds("PROXY_RUNTIME_REQUEST_TIMEOUT_SECONDS", 10*time.Second),
		IPRiskCheck: IPRiskCheck{
			Enabled:       envBool("PROXY_RUNTIME_IP_RISK_CHECK_ENABLED", false),
			URL:           envDefault("PROXY_RUNTIME_IP_RISK_CHECK_URL", "https://ip.net.coffee/api/ip/lookup/{ip}"),
			DiscoverURLs:  envListDefault("PROXY_RUNTIME_IP_RISK_DISCOVER_URLS", []string{"https://ipinfo.io/ip", "https://api.ipify.org", "https://ifconfig.me/ip"}),
			MaxAttempts:   envIntDefault("PROXY_RUNTIME_IP_RISK_MAX_ATTEMPTS", 3),
			Timeout:       envDurationSeconds("PROXY_RUNTIME_IP_RISK_TIMEOUT_SECONDS", 20*time.Second),
			MinTrustScore: envIntDefault("PROXY_RUNTIME_IP_RISK_MIN_TRUST_SCORE", 45),
		},
		Ten24: ten24.Config{
			APIURL:        strings.TrimSpace(os.Getenv("PROXY_RUNTIME_1024_API_URL")),
			APIRegion:     strings.TrimSpace(os.Getenv("PROXY_RUNTIME_1024_API_REGION")),
			APIFormat:     strings.TrimSpace(os.Getenv("PROXY_RUNTIME_1024_API_FORMAT")),
			APITime:       strings.TrimSpace(os.Getenv("PROXY_RUNTIME_1024_API_TIME")),
			APINum:        strings.TrimSpace(os.Getenv("PROXY_RUNTIME_1024_API_NUM")),
			APIType:       strings.TrimSpace(os.Getenv("PROXY_RUNTIME_1024_API_TYPE")),
			ProxyAddr:     strings.TrimSpace(os.Getenv("PROXY_RUNTIME_1024_PROXY_ADDR")),
			Username:      strings.TrimSpace(os.Getenv("PROXY_RUNTIME_1024_USERNAME")),
			Password:      strings.TrimSpace(os.Getenv("PROXY_RUNTIME_1024_PASSWORD")),
			Protocol:      envDefault("PROXY_RUNTIME_1024_PROTOCOL", "http"),
			Region:        strings.TrimSpace(os.Getenv("PROXY_RUNTIME_1024_REGION")),
			State:         strings.TrimSpace(os.Getenv("PROXY_RUNTIME_1024_STATE")),
			City:          strings.TrimSpace(os.Getenv("PROXY_RUNTIME_1024_CITY")),
			ASN:           strings.TrimSpace(os.Getenv("PROXY_RUNTIME_1024_ASN")),
			SessionID:     strings.TrimSpace(os.Getenv("PROXY_RUNTIME_1024_SESSION_ID")),
			StickyMinutes: envInt("PROXY_RUNTIME_1024_STICKY_MINUTES"),
		},
	}
	return cfg, cfg.validate()
}

func (c Config) validate() error {
	if c.RuntimeAddr == "" {
		return errors.New("PROXY_RUNTIME_ADDR is required")
	}
	if c.GostPath == "" {
		return errors.New("PROXY_RUNTIME_GOST_PATH is required")
	}
	if !isLocalProtocol(c.LocalProtocol) {
		return fmt.Errorf("unsupported local protocol %q", c.LocalProtocol)
	}
	if err := validateListeners(c.Listeners); err != nil {
		return err
	}
	if c.Provider != ProviderTen24 && c.Provider != ProviderNone && c.Provider != ProviderStatic {
		return ErrUnsupportedProvider
	}
	if c.Provider == ProviderStatic && len(c.SimpleProxies) == 0 {
		return errors.New("PROXY_RUNTIME_SIMPLE_PROXIES is required for static provider")
	}
	if c.Provider == ProviderTen24 {
		if err := c.Ten24.Validate(); err != nil {
			return err
		}
	}
	if c.RefreshInterval < 0 {
		return errors.New("PROXY_RUNTIME_REFRESH_SECONDS must be >= 0")
	}
	if c.RequestTimeout <= 0 {
		return errors.New("PROXY_RUNTIME_REQUEST_TIMEOUT_SECONDS must be > 0")
	}
	if c.IPRiskCheck.Enabled {
		if strings.TrimSpace(c.IPRiskCheck.URL) == "" {
			return errors.New("PROXY_RUNTIME_IP_RISK_CHECK_URL is required when risk check is enabled")
		}
		if c.IPRiskCheck.MaxAttempts <= 0 {
			return errors.New("PROXY_RUNTIME_IP_RISK_MAX_ATTEMPTS must be > 0")
		}
		if c.IPRiskCheck.Timeout <= 0 {
			return errors.New("PROXY_RUNTIME_IP_RISK_TIMEOUT_SECONDS must be > 0")
		}
		if len(c.IPRiskCheck.DiscoverURLs) == 0 {
			return errors.New("PROXY_RUNTIME_IP_RISK_DISCOVER_URLS is required when risk check is enabled")
		}
		if c.IPRiskCheck.MinTrustScore < 0 || c.IPRiskCheck.MinTrustScore > 100 {
			return errors.New("PROXY_RUNTIME_IP_RISK_MIN_TRUST_SCORE must be between 0 and 100")
		}
	}
	return nil
}

func validateListeners(listeners []EgressListener) error {
	seen := map[string]struct{}{}
	for index, listener := range listeners {
		id := strings.TrimSpace(listener.ID)
		if id == "" {
			return fmt.Errorf("PROXY_RUNTIME_LISTENERS_JSON[%d].id is required", index)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("duplicate proxy runtime listener id %q", id)
		}
		seen[id] = struct{}{}
		if strings.TrimSpace(listener.Addr) == "" {
			return fmt.Errorf("PROXY_RUNTIME_LISTENERS_JSON[%d].addr is required", index)
		}
		protocol := listener.Protocol
		if protocol == "" {
			protocol = "http"
		}
		if !isLocalProtocol(protocol) {
			return fmt.Errorf("unsupported listener protocol %q", listener.Protocol)
		}
		route := strings.TrimSpace(listener.Route)
		switch route {
		case "", ListenerRouteProvider, ListenerRouteDirect, ListenerRouteUpstream:
		default:
			return fmt.Errorf("unsupported listener route %q", listener.Route)
		}
		if route == ListenerRouteUpstream && strings.TrimSpace(listener.Upstream) == "" {
			return fmt.Errorf("PROXY_RUNTIME_LISTENERS_JSON[%d].upstream is required for upstream route", index)
		}
	}
	return nil
}

func isLocalProtocol(protocol string) bool {
	switch protocol {
	case "http", "socks5":
		return true
	default:
		return false
	}
}

func envDefault(name string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func envBool(name string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func envList(name string) []string {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func envListDefault(name string, fallback []string) []string {
	values := envList(name)
	if len(values) == 0 {
		return append([]string{}, fallback...)
	}
	return values
}

func envListeners(name string) []EgressListener {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil
	}
	var listeners []EgressListener
	if err := json.Unmarshal([]byte(raw), &listeners); err != nil {
		return []EgressListener{{
			ID:    "__invalid__",
			Addr:  "invalid",
			Route: fmt.Sprintf("invalid JSON: %v", err),
		}}
	}
	for index := range listeners {
		listeners[index].ID = strings.TrimSpace(listeners[index].ID)
		listeners[index].Addr = strings.TrimSpace(listeners[index].Addr)
		listeners[index].Protocol = strings.TrimSpace(listeners[index].Protocol)
		listeners[index].Route = strings.TrimSpace(listeners[index].Route)
		listeners[index].Upstream = strings.TrimSpace(listeners[index].Upstream)
		listeners[index].Username = strings.TrimSpace(listeners[index].Username)
		listeners[index].Password = strings.TrimSpace(listeners[index].Password)
	}
	return listeners
}

func envDurationSeconds(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	seconds, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

func envInt(name string) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return parsed
}

func envIntDefault(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
