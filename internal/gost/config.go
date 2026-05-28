package gost

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/byte-v-forge/proxy-runtime/internal/provider"
)

type Config struct {
	Services []Service `json:"services"`
	Chains   []Chain   `json:"chains,omitempty"`
	Bypasses []Bypass  `json:"bypasses,omitempty"`
}

type Service struct {
	Name     string   `json:"name"`
	Addr     string   `json:"addr"`
	Handler  Handler  `json:"handler"`
	Listener Listener `json:"listener"`
}

type Handler struct {
	Type  string `json:"type"`
	Chain string `json:"chain,omitempty"`
	Auth  *Auth  `json:"auth,omitempty"`
}

type Listener struct {
	Type string `json:"type"`
}

type Chain struct {
	Name string `json:"name"`
	Hops []Hop  `json:"hops"`
}

type Hop struct {
	Name   string `json:"name"`
	Nodes  []Node `json:"nodes"`
	Bypass string `json:"bypass,omitempty"`
}

type Node struct {
	Name      string    `json:"name"`
	Addr      string    `json:"addr"`
	Connector Connector `json:"connector"`
	Dialer    Dialer    `json:"dialer"`
}

type Connector struct {
	Type string `json:"type"`
	Auth *Auth  `json:"auth,omitempty"`
}

type Dialer struct {
	Type string `json:"type"`
}

type Auth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Bypass struct {
	Name      string   `json:"name"`
	Matchers  []string `json:"matchers"`
	Whitelist bool     `json:"whitelist,omitempty"`
	Reverse   bool     `json:"reverse,omitempty"`
}

type LocalService struct {
	Name            string
	Addr            string
	Protocol        string
	Username        string
	Password        string
	Route           string
	Upstream        string
	ProviderTargets []string
	ProviderNodes   []provider.Node
}

func BuildConfig(local LocalService, staticChain []*url.URL, pool []provider.Node) (Config, error) {
	return BuildEgressConfig(EgressConfig{
		Local:       local,
		StaticChain: staticChain,
		Pool:        pool,
	})
}

type EgressConfig struct {
	Common           *LocalService
	Local            LocalService
	Listeners        []LocalService
	StaticChain      []*url.URL
	Pool             []provider.Node
	DynamicViaCommon bool
}

func BuildEgressConfig(opts EgressConfig) (Config, error) {
	if len(opts.Listeners) > 0 {
		return buildListenerConfig(opts.Listeners, opts.StaticChain, opts.Pool)
	}

	local := opts.Local
	if strings.TrimSpace(local.Addr) == "" {
		return Config{}, errors.New("local proxy address is required")
	}

	staticChain := append([]*url.URL(nil), opts.StaticChain...)
	if opts.Common != nil && strings.TrimSpace(opts.Common.Addr) != "" && opts.DynamicViaCommon {
		commonURL, err := localServiceProxyURL(*opts.Common)
		if err != nil {
			return Config{}, err
		}
		staticChain = append([]*url.URL{commonURL}, staticChain...)
	}

	chain, err := buildChain(staticChain, opts.Pool)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{}
	if opts.Common != nil && strings.TrimSpace(opts.Common.Addr) != "" {
		cfg.Services = append(cfg.Services, buildService(*opts.Common, "common-egress", ""))
	}
	chainName := ""
	if len(chain.Hops) > 0 {
		chainName = chain.Name
		cfg.Chains = []Chain{chain}
	}
	cfg.Services = append(cfg.Services, buildService(local, "proxy-runtime", chainName))
	return cfg, nil
}

func buildListenerConfig(listeners []LocalService, staticChain []*url.URL, pool []provider.Node) (Config, error) {
	cfg := Config{}
	for _, listener := range listeners {
		serviceChain := ""
		switch normalizeListenerRoute(listener.Route) {
		case "provider":
			listenerPool := pool
			if listener.ProviderNodes != nil {
				listenerPool = listener.ProviderNodes
			}
			chain, err := buildNamedChain(safeChainName(listener.Name), staticChain, listenerPool, listener.ProviderTargets)
			if err != nil {
				return Config{}, err
			}
			if len(chain.Hops) > 0 {
				serviceChain = chain.Name
				cfg.Chains = append(cfg.Chains, chain)
				if len(listener.ProviderTargets) > 0 {
					cfg.Bypasses = append(cfg.Bypasses, providerTargetBypass(listener.Name, listener.ProviderTargets))
				}
			}
		case "direct":
			serviceChain = ""
		case "upstream":
			upstreamChain, err := buildUpstreamChain(listener)
			if err != nil {
				return Config{}, err
			}
			serviceChain = upstreamChain.Name
			cfg.Chains = append(cfg.Chains, upstreamChain)
		}
		cfg.Services = append(cfg.Services, buildService(listener, "proxy-runtime", serviceChain))
	}
	return cfg, nil
}

func buildListenerConfigOld(listeners []LocalService, staticChain []*url.URL, pool []provider.Node) (Config, error) {
	var providerTargets []string
	for _, listener := range listeners {
		if normalizeListenerRoute(listener.Route) == "provider" && len(listener.ProviderTargets) > 0 {
			providerTargets = listener.ProviderTargets
			break
		}
	}
	chain, err := buildChainWithProviderTargets(staticChain, pool, providerTargets)
	if err != nil {
		return Config{}, err
	}
	chainName := ""
	cfg := Config{}
	if len(chain.Hops) > 0 {
		chainName = chain.Name
		cfg.Chains = []Chain{chain}
		if len(providerTargets) > 0 {
			cfg.Bypasses = []Bypass{providerTargetBypass("", providerTargets)}
		}
	}
	for _, listener := range listeners {
		serviceChain := ""
		switch normalizeListenerRoute(listener.Route) {
		case "provider":
			serviceChain = chainName
		case "upstream":
			upstreamChain, err := buildUpstreamChain(listener)
			if err != nil {
				return Config{}, err
			}
			serviceChain = upstreamChain.Name
			cfg.Chains = append(cfg.Chains, upstreamChain)
		}
		cfg.Services = append(cfg.Services, buildService(listener, "proxy-runtime", serviceChain))
	}
	return cfg, nil
}

func buildService(local LocalService, fallbackName string, chainName string) Service {
	name := strings.TrimSpace(local.Name)
	if name == "" {
		name = fallbackName
	}
	handler := Handler{Type: normalizeLocalProtocol(local.Protocol)}
	if chainName != "" {
		handler.Chain = chainName
	}
	if local.Username != "" || local.Password != "" {
		handler.Auth = &Auth{Username: local.Username, Password: local.Password}
	}
	return Service{
		Name:     name,
		Addr:     local.Addr,
		Handler:  handler,
		Listener: Listener{Type: "tcp"},
	}
}

func buildChain(staticChain []*url.URL, pool []provider.Node) (Chain, error) {
	return buildChainWithProviderTargets(staticChain, pool, nil)
}

func buildChainWithProviderTargets(staticChain []*url.URL, pool []provider.Node, providerTargets []string) (Chain, error) {
	return buildNamedChain("default-chain", staticChain, pool, providerTargets)
}

func buildNamedChain(name string, staticChain []*url.URL, pool []provider.Node, providerTargets []string) (Chain, error) {
	chain := Chain{Name: strings.TrimSpace(name)}
	if chain.Name == "" {
		chain.Name = "default-chain"
	}
	for index, upstream := range staticChain {
		node, err := nodeFromURL(fmt.Sprintf("static-%d", index), upstream)
		if err != nil {
			return Chain{}, err
		}
		chain.Hops = append(chain.Hops, Hop{
			Name:  fmt.Sprintf("static-hop-%d", index),
			Nodes: []Node{node},
		})
	}
	if len(pool) > 0 {
		nodes := make([]Node, 0, len(pool))
		for index, item := range pool {
			node, err := nodeFromURL(fmt.Sprintf("pool-%d", index), item.URL)
			if err != nil {
				return Chain{}, err
			}
			nodes = append(nodes, node)
		}
		hop := Hop{Name: "provider-pool", Nodes: nodes}
		if len(providerTargets) > 0 {
			hop.Bypass = providerTargetBypassName(chain.Name)
		}
		chain.Hops = append(chain.Hops, hop)
	}
	return chain, nil
}

func providerTargetBypass(listenerName string, targets []string) Bypass {
	matchers := make([]string, 0, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target != "" {
			matchers = append(matchers, target)
		}
	}
	return Bypass{Name: providerTargetBypassName(safeChainName(listenerName)), Matchers: matchers, Whitelist: true, Reverse: true}
}

func providerTargetBypassName(chainName string) string {
	name := strings.TrimSuffix(strings.TrimSpace(chainName), "-chain")
	if name == "" || name == "default" {
		return "provider-targets"
	}
	return name + "-provider-targets"
}

func buildUpstreamChain(listener LocalService) (Chain, error) {
	proxyURL, err := provider.ParseProxy(listener.Upstream, "http")
	if err != nil {
		return Chain{}, fmt.Errorf("parse listener %q upstream: %w", listener.Name, err)
	}
	name := safeChainName(listener.Name)
	node, err := nodeFromURL("upstream-0", proxyURL)
	if err != nil {
		return Chain{}, err
	}
	return Chain{
		Name: name,
		Hops: []Hop{{
			Name:  "upstream-hop-0",
			Nodes: []Node{node},
		}},
	}, nil
}

func safeChainName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "listener-upstream-chain"
	}
	var out strings.Builder
	for _, r := range strings.ToLower(value) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			out.WriteRune(r)
			continue
		}
		out.WriteByte('-')
	}
	name := strings.Trim(out.String(), "-")
	if name == "" {
		name = "listener-upstream"
	}
	return name + "-chain"
}

func nodeFromURL(name string, proxyURL *url.URL) (Node, error) {
	if proxyURL == nil || proxyURL.Host == "" {
		return Node{}, errors.New("proxy node host is required")
	}
	connector, dialer := splitNodeScheme(proxyURL.Scheme)
	node := Node{
		Name:      name,
		Addr:      proxyURL.Host,
		Connector: Connector{Type: connector},
		Dialer:    Dialer{Type: dialer},
	}
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		node.Connector.Auth = &Auth{
			Username: proxyURL.User.Username(),
			Password: password,
		}
	}
	return node, nil
}

func localServiceProxyURL(local LocalService) (*url.URL, error) {
	addr := strings.TrimSpace(local.Addr)
	if addr == "" {
		return nil, errors.New("common egress address is required")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			host = "127.0.0.1"
			port = strings.TrimPrefix(addr, ":")
		} else {
			return nil, fmt.Errorf("parse common egress address: %w", err)
		}
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return &url.URL{
		Scheme: normalizeLocalProtocol(local.Protocol),
		Host:   net.JoinHostPort(host, port),
	}, nil
}

func splitNodeScheme(scheme string) (string, string) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "" {
		return "http", "tcp"
	}
	if scheme == "https" {
		return "http", "tls"
	}
	if strings.Contains(scheme, "+") {
		parts := strings.SplitN(scheme, "+", 2)
		return normalizeConnector(parts[0]), normalizeDialer(parts[1])
	}
	return normalizeConnector(scheme), "tcp"
}

func normalizeConnector(connector string) string {
	switch strings.ToLower(strings.TrimSpace(connector)) {
	case "socks5h":
		return "socks5"
	case "":
		return "http"
	default:
		return strings.ToLower(strings.TrimSpace(connector))
	}
}

func normalizeDialer(dialer string) string {
	if strings.TrimSpace(dialer) == "" {
		return "tcp"
	}
	return strings.ToLower(strings.TrimSpace(dialer))
}

func normalizeListenerRoute(route string) string {
	switch strings.ToLower(strings.TrimSpace(route)) {
	case "direct":
		return "direct"
	case "upstream":
		return "upstream"
	default:
		return "provider"
	}
}

func normalizeLocalProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "socks5":
		return "socks5"
	default:
		return "http"
	}
}
