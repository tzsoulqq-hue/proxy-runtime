package provider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"time"

	proxyruntimev1 "github.com/byte-v-forge/proxy-runtime/gen/byte/v/forge/contracts/proxyruntime/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Static struct {
	nodes []Node
}

func NewStatic(rawProxies []string) (*Static, error) {
	nodes := make([]Node, 0, len(rawProxies))
	for index, raw := range rawProxies {
		proxyURL, err := ParseProxy(raw, "http")
		if err != nil {
			return nil, fmt.Errorf("parse static proxy %d: %w", index, err)
		}
		nodes = append(nodes, Node{
			ID:           fmt.Sprintf("static-%d", index),
			URL:          proxyURL,
			Provider:     proxyruntimev1.ProxyProvider_PROXY_PROVIDER_STATIC,
			UpstreamKind: proxyruntimev1.ProxyUpstreamKind_PROXY_UPSTREAM_KIND_SIMPLE_PROXY,
			RotationMode: proxyruntimev1.ProxyRotationMode_PROXY_ROTATION_MODE_NONE,
			Labels: map[string]string{
				"mode": "simple_proxy",
			},
		})
	}
	return &Static{nodes: nodes}, nil
}

func (s *Static) Name() string {
	return "static"
}

func (s *Static) Descriptor() *proxyruntimev1.ProxyProviderDescriptor {
	return &proxyruntimev1.ProxyProviderDescriptor{
		ProviderId:  s.Name(),
		Provider:    proxyruntimev1.ProxyProvider_PROXY_PROVIDER_STATIC,
		DisplayName: "Static proxies",
		Capabilities: []proxyruntimev1.ProxyCapability{
			proxyruntimev1.ProxyCapability_PROXY_CAPABILITY_CHAINING,
			proxyruntimev1.ProxyCapability_PROXY_CAPABILITY_UNIFIED_EGRESS_GATEWAY,
		},
		Protocols: []proxyruntimev1.ProxyProtocol{
			proxyruntimev1.ProxyProtocol_PROXY_PROTOCOL_HTTP,
			proxyruntimev1.ProxyProtocol_PROXY_PROTOCOL_SOCKS5,
		},
		UpstreamKinds: []proxyruntimev1.ProxyUpstreamKind{
			proxyruntimev1.ProxyUpstreamKind_PROXY_UPSTREAM_KIND_SIMPLE_PROXY,
		},
		RotationModes: []proxyruntimev1.ProxyRotationMode{
			proxyruntimev1.ProxyRotationMode_PROXY_ROTATION_MODE_NONE,
		},
	}
}

func (s *Static) Fetch(context.Context, *proxyruntimev1.ProxySession) ([]Node, error) {
	nodes := make([]Node, len(s.nodes))
	for index, node := range s.nodes {
		clonedURL := *node.URL
		nodes[index] = node
		nodes[index].URL = &clonedURL
		nodes[index].Labels = cloneLabels(node.Labels)
	}
	return nodes, nil
}

func (s *Static) CreateSession(context.Context, *proxyruntimev1.CreateProxySessionRequest) (*proxyruntimev1.ProxySession, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate static proxy session id: %w", err)
	}
	now := time.Now().UTC()
	expiresAt := now.Add(30 * time.Minute)
	return &proxyruntimev1.ProxySession{
		SessionId: hex.EncodeToString(raw),
		Provider:  proxyruntimev1.ProxyProvider_PROXY_PROVIDER_STATIC,
		Policy: &proxyruntimev1.ProxySessionPolicy{
			Mode:             proxyruntimev1.ProxySessionMode_PROXY_SESSION_MODE_STICKY,
			UpstreamKind:     proxyruntimev1.ProxyUpstreamKind_PROXY_UPSTREAM_KIND_SIMPLE_PROXY,
			RotationMode:     proxyruntimev1.ProxyRotationMode_PROXY_ROTATION_MODE_NONE,
			StickyTtlMinutes: 30,
		},
		CreatedAt: timestamppb.New(now),
		ExpiresAt: timestamppb.New(expiresAt),
		Labels: map[string]string{
			"provider":     s.Name(),
			"session_mode": "static_compat",
		},
	}, nil
}

func StaticChainEndpoints(rawProxies []string) ([]*proxyruntimev1.ProxyEndpoint, error) {
	endpoints := make([]*proxyruntimev1.ProxyEndpoint, 0, len(rawProxies))
	for index, raw := range rawProxies {
		proxyURL, err := ParseProxy(raw, "http")
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, staticChainEndpoint(index, proxyURL))
	}
	return endpoints, nil
}

func staticChainEndpoint(index int, proxyURL *url.URL) *proxyruntimev1.ProxyEndpoint {
	return Node{
		ID:           fmt.Sprintf("chain-%d", index),
		URL:          proxyURL,
		Provider:     proxyruntimev1.ProxyProvider_PROXY_PROVIDER_STATIC,
		UpstreamKind: proxyruntimev1.ProxyUpstreamKind_PROXY_UPSTREAM_KIND_SIMPLE_PROXY,
		RotationMode: proxyruntimev1.ProxyRotationMode_PROXY_ROTATION_MODE_NONE,
		Labels: map[string]string{
			"mode": "chain_hop",
		},
	}.Endpoint()
}
