package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	proxyruntimev1 "github.com/byte-v-forge/proxy-runtime/gen/byte/v/forge/contracts/proxyruntime/v1"
	"github.com/byte-v-forge/proxy-runtime/internal/config"
	"golang.org/x/net/proxy"
)

type ipRiskResult struct {
	IP           string
	TrustScore   int
	Country      string
	CountryCode  string
	IsProxy      bool
	IsVPN        bool
	IsTor        bool
	IsAbuser     bool
	IsDatacenter bool
	Accepted     bool
}

type netCoffeeLookupResponse struct {
	IP           string `json:"ip"`
	TrustScore   int    `json:"trust_score"`
	Country      string `json:"country"`
	CountryCode  string `json:"countryCode"`
	IsProxy      bool   `json:"is_proxy"`
	IsVPN        bool   `json:"is_vpn"`
	IsTor        bool   `json:"is_tor"`
	IsAbuser     bool   `json:"is_abuser"`
	IsDatacenter bool   `json:"is_datacenter"`
	Error        string `json:"error"`
}

func (r *Runtime) checkActiveSessionRisk(ctx context.Context, listenerID string) (ipRiskResult, error) {
	ip := sessionPublicIP(r.currentSessionForListener(listenerID))
	if ip == "" {
		var err error
		ip, err = r.discoverActiveSessionIP(ctx, listenerID)
		if err != nil {
			return ipRiskResult{}, err
		}
	}
	return r.lookupIPRisk(ctx, ip)
}

func sessionPublicIP(session *proxyruntimev1.ProxySession) string {
	if session == nil {
		return ""
	}
	for _, key := range []string{"public_ip", "egress_ip", "ip", "risk_check_ip"} {
		value := strings.TrimSpace(session.GetLabels()[key])
		if net.ParseIP(value) != nil {
			return value
		}
	}
	return ""
}

func (r *Runtime) discoverActiveSessionIP(ctx context.Context, listenerID string) (string, error) {
	client, err := r.dynamicEgressHTTPClient(listenerID)
	if err != nil {
		return "", err
	}
	var lastErr error
	for _, discoverURL := range r.cfg.IPRiskCheck.DiscoverURLs {
		ip, err := requestPublicIP(ctx, client, discoverURL, r.cfg.IPRiskCheck.Timeout)
		if err == nil {
			return ip, nil
		}
		lastErr = err
		r.logger.Warn("proxy public IP discovery failed", "url", discoverURL, "error", err)
	}
	return "", fmt.Errorf("discover proxy public IP failed: %w", lastErr)
}

func requestPublicIP(ctx context.Context, client *http.Client, discoverURL string, timeout time.Duration) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, discoverURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("status=%d body=%s", resp.StatusCode, snippet(string(raw), 180))
	}
	ip := strings.TrimSpace(string(raw))
	if parsed := net.ParseIP(ip); parsed == nil {
		return "", fmt.Errorf("invalid IP: %s", snippet(ip, 120))
	}
	return ip, nil
}

func (r *Runtime) lookupIPRisk(ctx context.Context, ip string) (ipRiskResult, error) {
	lookupURL := strings.ReplaceAll(r.cfg.IPRiskCheck.URL, "{ip}", url.PathEscape(ip))
	reqCtx, cancel := context.WithTimeout(ctx, r.cfg.IPRiskCheck.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, lookupURL, nil)
	if err != nil {
		return ipRiskResult{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ipRiskResult{}, fmt.Errorf("lookup IP risk: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ipRiskResult{}, fmt.Errorf("read IP risk response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ipRiskResult{}, fmt.Errorf("lookup IP risk failed: status=%d body=%s", resp.StatusCode, snippet(string(raw), 240))
	}
	var parsed netCoffeeLookupResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return ipRiskResult{}, fmt.Errorf("parse IP risk response: %w", err)
	}
	if parsed.Error != "" {
		return ipRiskResult{}, fmt.Errorf("IP risk response error: %s", parsed.Error)
	}
	if parsed.IP == "" {
		parsed.IP = ip
	}
	result := ipRiskResult{
		IP:           parsed.IP,
		TrustScore:   parsed.TrustScore,
		Country:      parsed.Country,
		CountryCode:  strings.ToUpper(parsed.CountryCode),
		IsProxy:      parsed.IsProxy,
		IsVPN:        parsed.IsVPN,
		IsTor:        parsed.IsTor,
		IsAbuser:     parsed.IsAbuser,
		IsDatacenter: parsed.IsDatacenter,
	}
	result.Accepted = result.TrustScore >= r.cfg.IPRiskCheck.MinTrustScore && !result.IsTor && !result.IsAbuser
	return result, nil
}

func (r *Runtime) dynamicEgressHTTPClient(listenerID string) (*http.Client, error) {
	addr := r.providerListenerAddr(listenerID)
	if addr == "" {
		addr = r.cfg.LocalAddr
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	protocol := r.providerListenerProtocol(listenerID)
	if protocol == "" {
		protocol = r.cfg.LocalProtocol
	}
	transport := &http.Transport{}
	switch protocol {
	case "http":
		proxyURL := &url.URL{Scheme: "http", Host: addr}
		transport.Proxy = http.ProxyURL(proxyURL)
	case "socks5":
		dialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		transport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
			type contextDialer interface {
				DialContext(context.Context, string, string) (net.Conn, error)
			}
			if d, ok := dialer.(contextDialer); ok {
				return d.DialContext(ctx, network, address)
			}
			return dialer.Dial(network, address)
		}
	default:
		return nil, fmt.Errorf("unsupported provider listener protocol for risk check: %s", protocol)
	}
	return &http.Client{Timeout: r.cfg.IPRiskCheck.Timeout, Transport: transport}, nil
}

func (r *Runtime) providerListenerAddr(listenerID string) string {
	listenerID = strings.TrimSpace(listenerID)
	for _, listener := range r.listenerConfigs() {
		if listenerRoute(listener) == config.ListenerRouteProvider && (listenerID == "" || listener.ID == listenerID) {
			return strings.TrimSpace(listener.Addr)
		}
	}
	return ""
}

func (r *Runtime) providerListenerProtocol(listenerID string) string {
	listenerID = strings.TrimSpace(listenerID)
	for _, listener := range r.listenerConfigs() {
		if listenerRoute(listener) == config.ListenerRouteProvider && (listenerID == "" || listener.ID == listenerID) {
			return listenerProtocol(listener, r.cfg.LocalProtocol)
		}
	}
	return ""
}

func (result ipRiskResult) applyToSession(session *proxyruntimev1.ProxySession) {
	if session == nil {
		return
	}
	if session.Labels == nil {
		session.Labels = map[string]string{}
	}
	session.Labels["risk_check_status"] = "ok"
	session.Labels["risk_check_ip"] = result.IP
	session.Labels["risk_check_trust_score"] = fmt.Sprintf("%d", result.TrustScore)
	session.Labels["risk_check_country"] = result.CountryCode
	session.Labels["risk_check_proxy"] = fmt.Sprintf("%t", result.IsProxy)
	session.Labels["risk_check_vpn"] = fmt.Sprintf("%t", result.IsVPN)
	session.Labels["risk_check_tor"] = fmt.Sprintf("%t", result.IsTor)
	session.Labels["risk_check_abuser"] = fmt.Sprintf("%t", result.IsAbuser)
	session.Labels["risk_check_datacenter"] = fmt.Sprintf("%t", result.IsDatacenter)
	session.Labels["risk_check_accepted"] = fmt.Sprintf("%t", result.Accepted)
	session.Labels["risk_check_at"] = time.Now().UTC().Format(time.RFC3339)
}

func snippet(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}
