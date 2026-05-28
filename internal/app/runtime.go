package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	proxyruntimev1 "github.com/byte-v-forge/proxy-runtime/gen/byte/v/forge/contracts/proxyruntime/v1"
	"github.com/byte-v-forge/proxy-runtime/internal/config"
	"github.com/byte-v-forge/proxy-runtime/internal/gost"
	"github.com/byte-v-forge/proxy-runtime/internal/provider"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Runtime struct {
	cfg      config.Config
	provider provider.Provider
	manager  *gost.Manager
	logger   *slog.Logger

	mu               sync.RWMutex
	pool             []provider.Node
	activeSession    *proxyruntimev1.ProxySession
	listenerPools    map[string][]provider.Node
	activeSessions   map[string]*proxyruntimev1.ProxySession
	dynamicListeners []config.EgressListener
	refreshedAt      time.Time

	refreshMu        sync.Mutex
	forwardMu        sync.Mutex
	forwardCancel    context.CancelFunc
	forwardListeners []net.Listener
	forwardSignature string
}

func NewRuntime(cfg config.Config, proxyProvider provider.Provider, manager *gost.Manager, logger *slog.Logger) *Runtime {
	if logger == nil {
		logger = slog.Default()
	}
	return &Runtime{
		cfg:            cfg,
		provider:       proxyProvider,
		manager:        manager,
		logger:         logger,
		listenerPools:  map[string][]provider.Node{},
		activeSessions: map[string]*proxyruntimev1.ProxySession{},
	}
}

func (r *Runtime) Run(ctx context.Context) error {
	if err := r.refresh(ctx); err != nil {
		return err
	}
	defer r.manager.Stop()
	defer r.stopForwarders()

	errCh := make(chan error, 2)
	go r.refreshLoop(ctx, errCh)
	go r.serveHTTP(ctx, errCh)

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func (r *Runtime) refreshLoop(ctx context.Context, errCh chan<- error) {
	if r.cfg.RefreshInterval == 0 {
		return
	}
	ticker := time.NewTicker(r.cfg.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.refresh(ctx); err != nil {
				r.logger.Warn("proxy pool refresh failed", "provider", r.provider.Name(), "error", err)
			}
		}
	}
}

func (r *Runtime) refresh(ctx context.Context) error {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()

	pools, sessions, err := r.fetchProviderPools(ctx)
	if err != nil {
		return err
	}
	nodes := pools[""]
	staticChain, err := r.parseStaticChain()
	if err != nil {
		return err
	}
	if len(nodes) == 0 && len(staticChain) == 0 && r.cfg.Provider != config.ProviderNone {
		return errors.New("proxy pool is empty")
	}
	gostConfig, err := r.buildGostConfig(staticChain, nodes, pools)
	if err != nil {
		return err
	}
	if err := r.manager.Reload(ctx, gostConfig); err != nil {
		return err
	}
	if err := r.reloadForwarders(ctx); err != nil {
		return err
	}

	r.mu.Lock()
	r.pool = append([]provider.Node(nil), nodes...)
	r.listenerPools = cloneListenerPools(pools)
	for listenerID, session := range sessions {
		if session != nil {
			r.activeSessions[listenerID] = session
		}
	}
	r.refreshedAt = time.Now().UTC()
	r.mu.Unlock()

	r.logger.Info("proxy runtime refreshed", "provider", r.provider.Name(), "pool_size", len(nodes), "static_chain_size", len(staticChain))
	return nil
}

func (r *Runtime) fetchProviderPools(ctx context.Context) (map[string][]provider.Node, map[string]*proxyruntimev1.ProxySession, error) {
	pools := map[string][]provider.Node{}
	sessions := map[string]*proxyruntimev1.ProxySession{}
	listenerIDs := r.providerListenerIDs()
	if len(listenerIDs) == 0 {
		session := r.currentSession()
		nodes, err := r.provider.Fetch(ctx, session)
		if err != nil {
			return nil, nil, err
		}
		pools[""] = nodes
		sessions[""] = session
		return pools, sessions, nil
	}
	for _, listenerID := range listenerIDs {
		session := r.currentSessionForListener(listenerID)
		nodes, err := r.provider.Fetch(ctx, session)
		if err != nil {
			return nil, nil, err
		}
		pools[listenerID] = nodes
		pools[""] = append(pools[""], nodes...)
		if session != nil {
			sessions[listenerID] = session
		}
	}
	return pools, sessions, nil
}

func cloneListenerPools(in map[string][]provider.Node) map[string][]provider.Node {
	out := make(map[string][]provider.Node, len(in))
	for key, nodes := range in {
		out[key] = append([]provider.Node(nil), nodes...)
	}
	return out
}

func (r *Runtime) buildGostConfig(staticChain []*url.URL, nodes []provider.Node, pools map[string][]provider.Node) (gost.Config, error) {
	if r.usesListenerCatalog() {
		return gost.BuildEgressConfig(gost.EgressConfig{
			Listeners:   r.gostListeners(pools),
			StaticChain: staticChain,
			Pool:        nodes,
		})
	}
	return gost.BuildEgressConfig(gost.EgressConfig{
		Common: r.commonEgressService(),
		Local: gost.LocalService{
			Name:     "dynamic-egress",
			Addr:     r.cfg.LocalAddr,
			Protocol: r.cfg.LocalProtocol,
			Username: r.cfg.LocalUsername,
			Password: r.cfg.LocalPassword,
		},
		StaticChain:      staticChain,
		Pool:             nodes,
		DynamicViaCommon: r.cfg.CommonEgressAddr != "",
	})
}

func (r *Runtime) parseStaticChain() ([]*url.URL, error) {
	nodes := make([]*url.URL, 0, len(r.cfg.StaticChain))
	for _, raw := range r.cfg.StaticChain {
		parsed, err := provider.ParseProxy(raw, "http")
		if err != nil {
			return nil, fmt.Errorf("parse static chain proxy: %w", err)
		}
		nodes = append(nodes, parsed)
	}
	return nodes, nil
}

func (r *Runtime) commonEgressService() *gost.LocalService {
	if r.cfg.CommonEgressAddr == "" {
		return nil
	}
	return &gost.LocalService{
		Name:     "common-egress",
		Addr:     r.cfg.CommonEgressAddr,
		Protocol: r.cfg.LocalProtocol,
		Username: r.cfg.LocalUsername,
		Password: r.cfg.LocalPassword,
	}
}

func (r *Runtime) serveHTTP(ctx context.Context, errCh chan<- error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", r.handleHealth)
	mux.HandleFunc("/readyz", r.handleReady)
	mux.HandleFunc("/proxy/providers", r.handleProviders)
	mux.HandleFunc("/proxy/gateway", r.handleGateway)
	mux.HandleFunc("/proxy/pool", r.handlePool)
	mux.HandleFunc("/proxy/refresh", r.handleRefresh)
	mux.HandleFunc("/proxy/session/new", r.handleNewSession)
	mux.HandleFunc("/proxy/listeners", r.handleListeners)
	mux.HandleFunc("/api/proxy-runtime/providers", r.handleProviders)
	mux.HandleFunc("/api/proxy-runtime/gateway", r.handleGateway)
	mux.HandleFunc("/api/proxy-runtime/pool", r.handlePool)
	mux.HandleFunc("/api/proxy-runtime/refresh", r.handleRefresh)
	mux.HandleFunc("/api/proxy-runtime/session/new", r.handleNewSession)
	mux.HandleFunc("/api/proxy-runtime/listeners", r.handleListeners)

	server := &http.Server{
		Addr:              r.cfg.RuntimeAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	r.logger.Info("proxy-runtime http listening", "addr", r.cfg.RuntimeAddr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errCh <- fmt.Errorf("serve proxy-runtime http: %w", err)
	}
}

func (r *Runtime) handleHealth(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (r *Runtime) handleReady(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !r.manager.Status().Running {
		http.Error(w, "gost is not running", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (r *Runtime) handlePool(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.writeProto(w, &proxyruntimev1.GetProxyPoolResponse{Pool: r.snapshot()})
}

func (r *Runtime) handleProviders(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.writeProto(w, &proxyruntimev1.ListProxyProvidersResponse{
		Providers: []*proxyruntimev1.ProxyProviderDescriptor{r.provider.Descriptor()},
	})
}

func (r *Runtime) handleGateway(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	gateway, err := r.gateway()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	r.writeProto(w, &proxyruntimev1.GetEgressGatewayResponse{Gateway: gateway})
}

func (r *Runtime) handleRefresh(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.refresh(req.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	r.writeProto(w, &proxyruntimev1.RefreshProxyPoolResponse{Pool: r.snapshot()})
}

func (r *Runtime) handleNewSession(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var createReq proxyruntimev1.CreateProxySessionRequest
	listenerID := strings.TrimSpace(req.URL.Query().Get("listener_id"))
	if req.Body != nil && req.ContentLength != 0 {
		body, err := readRequestBody(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		listenerID = firstNonEmptyString(listenerID, listenerIDFromCreateSessionJSON(body))
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &createReq); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	listenerID = firstNonEmptyString(listenerID, listenerIDFromCreateSessionRequest(&createReq))
	session, err := r.createCheckedSession(req.Context(), &createReq, listenerID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r.writeProto(w, &proxyruntimev1.CreateProxySessionResponse{
		Session: session,
		Pool:    r.snapshot(),
	})
}

func (r *Runtime) createCheckedSession(ctx context.Context, createReq *proxyruntimev1.CreateProxySessionRequest, listenerID string) (*proxyruntimev1.ProxySession, error) {
	listenerID = strings.TrimSpace(listenerID)
	if listenerID != "" && !r.providerListenerIDExists(listenerID) {
		return nil, fmt.Errorf("provider listener %q not found", listenerID)
	}
	attempts := 1
	if r.cfg.IPRiskCheck.Enabled {
		attempts = r.cfg.IPRiskCheck.MaxAttempts
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		session, err := r.provider.CreateSession(ctx, createReq)
		if err != nil {
			return nil, err
		}
		if session.Labels == nil {
			session.Labels = map[string]string{}
		}
		session.Labels["risk_check_attempt"] = fmt.Sprintf("%d", attempt)
		if listenerID != "" {
			session.Labels["listener_id"] = listenerID
		}

		r.mu.Lock()
		if listenerID == "" {
			r.activeSession = session
		} else {
			r.activeSessions[listenerID] = session
		}
		r.mu.Unlock()
		if err := r.refresh(ctx); err != nil {
			return nil, err
		}
		if !r.cfg.IPRiskCheck.Enabled {
			return session, nil
		}
		result, err := r.checkActiveSessionRisk(ctx, listenerID)
		if err != nil {
			lastErr = err
			session.Labels["risk_check_status"] = "error"
			session.Labels["risk_check_error"] = snippet(err.Error(), 180)
			r.logger.Warn("proxy session risk check failed", "attempt", attempt, "error", err)
			continue
		}
		result.applyToSession(session)
		if result.Accepted {
			r.logger.Info("proxy session risk check accepted", "attempt", attempt, "ip", result.IP, "trust_score", result.TrustScore)
			return session, nil
		}
		lastErr = fmt.Errorf("IP risk rejected ip=%s trust_score=%d min=%d", result.IP, result.TrustScore, r.cfg.IPRiskCheck.MinTrustScore)
		r.logger.Warn("proxy session risk check rejected", "attempt", attempt, "ip", result.IP, "trust_score", result.TrustScore, "min", r.cfg.IPRiskCheck.MinTrustScore)
	}
	if lastErr == nil {
		lastErr = errors.New("proxy session risk check failed")
	}
	return nil, fmt.Errorf("no acceptable proxy session after %d attempts: %w", attempts, lastErr)
}

func (r *Runtime) handleListeners(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		r.writeProto(w, &proxyruntimev1.ListEgressListenersResponse{Listeners: r.protoListeners()})
	case http.MethodPost:
		r.createListener(w, req)
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (r *Runtime) createListener(w http.ResponseWriter, req *http.Request) {
	var createReq proxyruntimev1.CreateEgressListenerRequest
	if req.Body == nil {
		http.Error(w, "request body is required", http.StatusBadRequest)
		return
	}
	body, err := readRequestBody(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &createReq); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	listener, err := listenerFromCreateRequest(&createReq, r.cfg.LocalProtocol)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := r.addDynamicListener(req.Context(), listener); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	gateway, err := r.gateway()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	r.writeProto(w, &proxyruntimev1.CreateEgressListenerResponse{
		Listener: protoListener(listener, true),
		Gateway:  gateway,
	})
}

func (r *Runtime) addDynamicListener(ctx context.Context, listener config.EgressListener) error {
	r.mu.Lock()
	if r.listenerIDExistsLocked(listener.ID) {
		r.mu.Unlock()
		return fmt.Errorf("listener %q already exists", listener.ID)
	}
	r.dynamicListeners = append(r.dynamicListeners, listener)
	r.mu.Unlock()

	if err := r.refresh(ctx); err != nil {
		r.mu.Lock()
		r.removeDynamicListenerLocked(listener.ID)
		r.mu.Unlock()
		return err
	}
	return nil
}

func (r *Runtime) listenerIDExistsLocked(id string) bool {
	for _, listener := range r.cfg.Listeners {
		if listener.ID == id {
			return true
		}
	}
	for _, listener := range r.dynamicListeners {
		if listener.ID == id {
			return true
		}
	}
	return false
}

func (r *Runtime) removeDynamicListenerLocked(id string) {
	for index, listener := range r.dynamicListeners {
		if listener.ID == id {
			r.dynamicListeners = append(r.dynamicListeners[:index], r.dynamicListeners[index+1:]...)
			return
		}
	}
}

func (r *Runtime) snapshot() *proxyruntimev1.ProxyPoolSnapshot {
	r.mu.RLock()
	nodes := append([]provider.Node(nil), r.pool...)
	session := r.activeSession
	if session == nil {
		for _, candidate := range r.activeSessions {
			if candidate != nil {
				session = candidate
				break
			}
		}
	}
	refreshedAt := r.refreshedAt
	r.mu.RUnlock()

	endpoints := make([]*proxyruntimev1.ProxyEndpoint, 0, len(nodes))
	for _, node := range nodes {
		endpoints = append(endpoints, node.Endpoint())
	}
	return &proxyruntimev1.ProxyPoolSnapshot{
		PoolId:        "default",
		Provider:      r.provider.Descriptor(),
		ActiveSession: session,
		Endpoints:     endpoints,
		RefreshedAt:   timestamppb.New(refreshedAt),
	}
}

func (r *Runtime) gateway() (*proxyruntimev1.EgressGateway, error) {
	dataRoute, err := r.dataPlaneRoute()
	if err != nil {
		return nil, err
	}
	controlRoute, err := r.controlPlaneRoute()
	if err != nil {
		return nil, err
	}
	return &proxyruntimev1.EgressGateway{
		GatewayId:         "default",
		Listeners:         r.protoListeners(),
		Pool:              r.snapshot(),
		DataPlaneRoute:    dataRoute,
		ControlPlaneRoute: controlRoute,
		ProviderControlPlane: &proxyruntimev1.ProviderControlPlaneAccess{
			UsesProxy: r.cfg.ProviderHTTPProxy != "",
			ProxyRef:  providerHTTPProxyRef(r.cfg.ProviderHTTPProxy),
			Protocols: []proxyruntimev1.ProxyProtocol{proxyruntimev1.ProxyProtocol_PROXY_PROTOCOL_HTTP},
		},
		UpdatedAt: timestamppb.Now(),
	}, nil
}

func (r *Runtime) dataPlaneRoute() (*proxyruntimev1.EgressRoute, error) {
	route := &proxyruntimev1.EgressRoute{RouteId: "default-data-plane"}
	if r.cfg.CommonEgressAddr != "" {
		commonEndpoint, err := r.localEgressEndpoint("common-egress", r.cfg.CommonEgressAddr)
		if err != nil {
			return nil, err
		}
		route.Hops = append(route.Hops, &proxyruntimev1.EgressHop{
			HopId: "common-egress",
			Order: 1,
			Role:  proxyruntimev1.EgressHopRole_EGRESS_HOP_ROLE_FORWARD,
			Selector: &proxyruntimev1.ProxySelectorPolicy{
				Strategy: proxyruntimev1.ProxySelectorStrategy_PROXY_SELECTOR_STRATEGY_FIFO,
			},
			Endpoints: []*proxyruntimev1.ProxyEndpoint{commonEndpoint},
		})
	}
	chain, err := provider.StaticChainEndpoints(r.cfg.StaticChain)
	if err != nil {
		return nil, err
	}
	for index, endpoint := range chain {
		route.Hops = append(route.Hops, &proxyruntimev1.EgressHop{
			HopId: fmt.Sprintf("forward-%d", index),
			Order: uint32(len(route.Hops) + 1),
			Role:  proxyruntimev1.EgressHopRole_EGRESS_HOP_ROLE_FORWARD,
			Selector: &proxyruntimev1.ProxySelectorPolicy{
				Strategy: proxyruntimev1.ProxySelectorStrategy_PROXY_SELECTOR_STRATEGY_FIFO,
			},
			Endpoints: []*proxyruntimev1.ProxyEndpoint{endpoint},
		})
	}
	pool := r.snapshot()
	if len(pool.Endpoints) > 0 {
		route.Hops = append(route.Hops, &proxyruntimev1.EgressHop{
			HopId: fmt.Sprintf("exit-%d", len(route.Hops)),
			Order: uint32(len(route.Hops) + 1),
			Role:  proxyruntimev1.EgressHopRole_EGRESS_HOP_ROLE_EXIT,
			Selector: &proxyruntimev1.ProxySelectorPolicy{
				Strategy: proxyruntimev1.ProxySelectorStrategy_PROXY_SELECTOR_STRATEGY_ROUND_ROBIN,
			},
			Endpoints: pool.Endpoints,
		})
	}
	return route, nil
}

func (r *Runtime) usesListenerCatalog() bool {
	r.mu.RLock()
	hasDynamic := len(r.dynamicListeners) > 0
	r.mu.RUnlock()
	return len(r.cfg.Listeners) > 0 || hasDynamic
}

func (r *Runtime) listenerConfigs() []config.EgressListener {
	r.mu.RLock()
	dynamic := append([]config.EgressListener(nil), r.dynamicListeners...)
	r.mu.RUnlock()

	if len(r.cfg.Listeners) > 0 {
		listeners := append([]config.EgressListener(nil), r.cfg.Listeners...)
		return append(listeners, dynamic...)
	}
	if len(dynamic) == 0 {
		return nil
	}
	listeners := r.defaultListenerConfigs()
	return append(listeners, dynamic...)
}

func (r *Runtime) upstreamListenerConfigs() []config.EgressListener {
	configs := r.listenerConfigs()
	upstreams := make([]config.EgressListener, 0, len(configs))
	for _, listener := range configs {
		if listenerRoute(listener) == config.ListenerRouteUpstream {
			upstreams = append(upstreams, listener)
		}
	}
	return upstreams
}

func (r *Runtime) defaultListenerConfigs() []config.EgressListener {
	listeners := []config.EgressListener{}
	if r.cfg.CommonEgressAddr != "" {
		listeners = append(listeners, config.EgressListener{
			ID:       "common-egress",
			Addr:     r.cfg.CommonEgressAddr,
			Protocol: r.cfg.LocalProtocol,
			Route:    config.ListenerRouteDirect,
		})
	}
	listeners = append(listeners, config.EgressListener{
		ID:       "dynamic-egress",
		Addr:     r.cfg.LocalAddr,
		Protocol: r.cfg.LocalProtocol,
		Route:    config.ListenerRouteProvider,
	})
	return listeners
}

func (r *Runtime) gostListeners(pools map[string][]provider.Node) []gost.LocalService {
	configs := r.listenerConfigs()
	listenerPools := cloneListenerPools(pools)
	if len(listenerPools) == 0 {
		r.mu.RLock()
		listenerPools = cloneListenerPools(r.listenerPools)
		r.mu.RUnlock()
	}
	services := make([]gost.LocalService, 0, len(configs))
	for _, listener := range configs {
		if listenerRoute(listener) == config.ListenerRouteUpstream {
			continue
		}
		services = append(services, gost.LocalService{
			Name:            listener.ID,
			Addr:            listener.Addr,
			Protocol:        listenerProtocol(listener, r.cfg.LocalProtocol),
			Username:        listener.Username,
			Password:        listener.Password,
			Route:           listenerRoute(listener),
			Upstream:        listener.Upstream,
			ProviderTargets: r.cfg.ProviderTargets,
			ProviderNodes:   listenerPools[listener.ID],
		})
	}
	return services
}

func (r *Runtime) providerListenerIDs() []string {
	configs := r.listenerConfigs()
	if len(configs) == 0 {
		configs = r.defaultListenerConfigs()
	}
	ids := make([]string, 0, len(configs))
	for _, listener := range configs {
		if listenerRoute(listener) == config.ListenerRouteProvider {
			ids = append(ids, listener.ID)
		}
	}
	return ids
}

func (r *Runtime) providerListenerIDExists(listenerID string) bool {
	listenerID = strings.TrimSpace(listenerID)
	if listenerID == "" {
		return true
	}
	for _, id := range r.providerListenerIDs() {
		if id == listenerID {
			return true
		}
	}
	return false
}

func (r *Runtime) reloadForwarders(_ context.Context) error {
	listeners := r.upstreamListenerConfigs()
	signature := upstreamForwarderSignature(listeners)
	r.forwardMu.Lock()
	if r.forwardSignature == signature {
		r.forwardMu.Unlock()
		return nil
	}
	r.forwardMu.Unlock()

	r.stopForwarders()
	if len(listeners) == 0 {
		r.forwardMu.Lock()
		r.forwardSignature = signature
		r.forwardMu.Unlock()
		return nil
	}
	forwardCtx, cancel := context.WithCancel(context.Background())
	started := make([]net.Listener, 0, len(listeners))
	for _, listener := range listeners {
		upstream, err := provider.ParseProxy(listener.Upstream, "socks5")
		if err != nil {
			closeListeners(started)
			cancel()
			return fmt.Errorf("parse listener %q upstream: %w", listener.ID, err)
		}
		ln, err := net.Listen("tcp", listener.Addr)
		if err != nil {
			closeListeners(started)
			cancel()
			return fmt.Errorf("listen upstream forwarder %q: %w", listener.ID, err)
		}
		started = append(started, ln)
		go r.serveForwarder(forwardCtx, listener.ID, ln, upstream.Host)
	}

	r.forwardMu.Lock()
	r.forwardCancel = cancel
	r.forwardListeners = started
	r.forwardSignature = signature
	r.forwardMu.Unlock()
	return nil
}

func (r *Runtime) stopForwarders() {
	r.forwardMu.Lock()
	cancel := r.forwardCancel
	listeners := r.forwardListeners
	r.forwardCancel = nil
	r.forwardListeners = nil
	r.forwardSignature = ""
	r.forwardMu.Unlock()
	if cancel != nil {
		cancel()
	}
	closeListeners(listeners)
}

func closeListeners(listeners []net.Listener) {
	for _, ln := range listeners {
		_ = ln.Close()
	}
}

func upstreamForwarderSignature(listeners []config.EgressListener) string {
	if len(listeners) == 0 {
		return "[]"
	}
	var b strings.Builder
	for _, listener := range listeners {
		b.WriteString(listener.ID)
		b.WriteByte('\x00')
		b.WriteString(listener.Addr)
		b.WriteByte('\x00')
		b.WriteString(listener.Upstream)
		b.WriteByte('\x00')
		b.WriteString(listener.Protocol)
		b.WriteByte('\x00')
		b.WriteString(listener.Route)
		b.WriteByte('\x00')
	}
	return b.String()
}

func (r *Runtime) serveForwarder(ctx context.Context, listenerID string, ln net.Listener, upstreamAddr string) {
	r.logger.Info("proxy-runtime tcp forwarder listening", "listener", listenerID, "addr", ln.Addr().String(), "upstream", upstreamAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				r.logger.Debug("proxy-runtime tcp forwarder stopped", "listener", listenerID, "error", err)
			}
			return
		}
		go r.forwardConn(ctx, listenerID, conn, upstreamAddr)
	}
}

func (r *Runtime) forwardConn(ctx context.Context, listenerID string, client net.Conn, upstreamAddr string) {
	defer client.Close()
	dialer := net.Dialer{Timeout: 10 * time.Second}
	upstream, err := dialer.DialContext(ctx, "tcp", upstreamAddr)
	if err != nil {
		r.logger.Warn("proxy-runtime tcp forwarder dial failed", "listener", listenerID, "error", err)
		return
	}
	defer upstream.Close()

	done := make(chan struct{}, 2)
	copyConn := func(dst net.Conn, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go copyConn(upstream, client)
	go copyConn(client, upstream)

	select {
	case <-ctx.Done():
	case <-done:
	}
}

func (r *Runtime) protoListeners() []*proxyruntimev1.EgressListener {
	configs := r.listenerConfigs()
	if len(configs) == 0 {
		configs = r.defaultListenerConfigs()
	}
	listeners := make([]*proxyruntimev1.EgressListener, 0, len(configs))
	configuredCount := len(r.cfg.Listeners)
	for index, listener := range configs {
		managed := configuredCount == 0 || index >= configuredCount
		listeners = append(listeners, protoListener(listener, managed))
	}
	return listeners
}

func protoListener(listener config.EgressListener, managed bool) *proxyruntimev1.EgressListener {
	route := listenerRoute(listener)
	kind := proxyruntimev1.EgressListenerKind_EGRESS_LISTENER_KIND_PROVIDER_ROUTE
	routeID := "default-data-plane"
	if route == config.ListenerRouteDirect {
		kind = proxyruntimev1.EgressListenerKind_EGRESS_LISTENER_KIND_DIRECT
		routeID = "direct"
	}
	labels := listener.Labels
	if route == config.ListenerRouteUpstream {
		routeID = listener.ID + "-chain"
		labels = cloneLabels(labels)
		labels["route"] = config.ListenerRouteUpstream
	}
	return &proxyruntimev1.EgressListener{
		ListenerId: listener.ID,
		Kind:       kind,
		ListenAddr: listener.Addr,
		Protocol:   protocolFromName(listenerProtocol(listener, "http")),
		RouteId:    routeID,
		Managed:    managed,
		Labels:     labels,
	}
}

func listenerFromCreateRequest(req *proxyruntimev1.CreateEgressListenerRequest, defaultProtocol string) (config.EgressListener, error) {
	id := strings.TrimSpace(req.GetListenerId())
	if id == "" {
		return config.EgressListener{}, errors.New("listener_id is required")
	}
	addr := strings.TrimSpace(req.GetListenAddr())
	if addr == "" {
		return config.EgressListener{}, errors.New("listen_addr is required")
	}
	protocol := defaultProtocol
	if req.GetProtocol() != proxyruntimev1.ProxyProtocol_PROXY_PROTOCOL_UNSPECIFIED {
		protocol = protocolName(req.GetProtocol())
	}
	route := config.ListenerRouteProvider
	if req.GetKind() == proxyruntimev1.EgressListenerKind_EGRESS_LISTENER_KIND_DIRECT {
		route = config.ListenerRouteDirect
	}
	return config.EgressListener{
		ID:       id,
		Addr:     addr,
		Protocol: protocol,
		Route:    route,
		Labels:   req.GetLabels(),
	}, nil
}

func listenerProtocol(listener config.EgressListener, fallback string) string {
	protocol := strings.TrimSpace(listener.Protocol)
	if protocol == "" {
		return fallback
	}
	return protocol
}

func listenerRoute(listener config.EgressListener) string {
	switch strings.TrimSpace(listener.Route) {
	case config.ListenerRouteDirect:
		return config.ListenerRouteDirect
	case config.ListenerRouteUpstream:
		return config.ListenerRouteUpstream
	default:
		return config.ListenerRouteProvider
	}
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return map[string]string{}
	}
	cloned := make(map[string]string, len(labels))
	for key, value := range labels {
		cloned[key] = value
	}
	return cloned
}

func (r *Runtime) localEgressEndpoint(id string, addr string) (*proxyruntimev1.ProxyEndpoint, error) {
	target := addr
	if strings.HasPrefix(strings.TrimSpace(addr), ":") {
		target = "127.0.0.1" + strings.TrimSpace(addr)
	}
	endpoint, err := provider.ParseProxy(target, r.cfg.LocalProtocol)
	if err != nil {
		return nil, err
	}
	return &proxyruntimev1.ProxyEndpoint{
		Id:           id,
		Provider:     proxyruntimev1.ProxyProvider_PROXY_PROVIDER_STATIC,
		Protocol:     protocolFromName(r.cfg.LocalProtocol),
		Host:         endpoint.Hostname(),
		Port:         portFromURL(endpoint),
		UpstreamKind: proxyruntimev1.ProxyUpstreamKind_PROXY_UPSTREAM_KIND_SIMPLE_PROXY,
		RotationMode: proxyruntimev1.ProxyRotationMode_PROXY_ROTATION_MODE_NONE,
		Labels:       map[string]string{"mode": "local_egress"},
	}, nil
}

func (r *Runtime) controlPlaneRoute() (*proxyruntimev1.EgressRoute, error) {
	if r.cfg.ProviderHTTPProxy == "" {
		return nil, nil
	}
	endpoint, err := provider.ParseProxy(r.cfg.ProviderHTTPProxy, "http")
	if err != nil {
		return nil, err
	}
	return &proxyruntimev1.EgressRoute{
		RouteId: "provider-control-plane",
		Hops: []*proxyruntimev1.EgressHop{{
			HopId: "control-plane-proxy",
			Order: 1,
			Role:  proxyruntimev1.EgressHopRole_EGRESS_HOP_ROLE_CONTROL_PLANE,
			Selector: &proxyruntimev1.ProxySelectorPolicy{
				Strategy: proxyruntimev1.ProxySelectorStrategy_PROXY_SELECTOR_STRATEGY_FIFO,
			},
			Endpoints: []*proxyruntimev1.ProxyEndpoint{{
				Id:           "provider-http-proxy",
				Provider:     proxyruntimev1.ProxyProvider_PROXY_PROVIDER_STATIC,
				Protocol:     protocolFromURL(endpoint),
				Host:         endpoint.Hostname(),
				Port:         portFromURL(endpoint),
				UpstreamKind: proxyruntimev1.ProxyUpstreamKind_PROXY_UPSTREAM_KIND_SIMPLE_PROXY,
				RotationMode: proxyruntimev1.ProxyRotationMode_PROXY_ROTATION_MODE_NONE,
				Labels:       map[string]string{"mode": "provider_control_plane"},
			}},
		}},
	}, nil
}

func (r *Runtime) currentSession() *proxyruntimev1.ProxySession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.activeSession
}

func (r *Runtime) currentSessionForListener(listenerID string) *proxyruntimev1.ProxySession {
	listenerID = strings.TrimSpace(listenerID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if listenerID != "" {
		if session := r.activeSessions[listenerID]; session != nil {
			return session
		}
	}
	return r.activeSession
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func listenerIDFromCreateSessionRequest(req *proxyruntimev1.CreateProxySessionRequest) string {
	if req == nil {
		return ""
	}
	if value := strings.TrimSpace(req.GetProviderId()); value != "" && !strings.Contains(value, "://") {
		return value
	}
	if req.GetPolicy() == nil {
		return ""
	}
	return firstNonEmptyString(
		req.GetPolicy().GetLabels()["listener_id"],
		req.GetPolicy().GetLabels()["proxy_listener_id"],
		req.GetPolicy().GetLabels()["egress_listener_id"],
	)
}

func listenerIDFromCreateSessionJSON(body []byte) string {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return ""
	}
	if value := stringMapValue(raw, "listener_id"); value != "" {
		return value
	}
	if value := stringMapValue(raw, "proxy_listener_id"); value != "" {
		return value
	}
	policy, _ := raw["policy"].(map[string]any)
	if len(policy) == 0 {
		return ""
	}
	if value := stringMapValue(policy, "listener_id"); value != "" {
		return value
	}
	labels, _ := policy["labels"].(map[string]any)
	return firstNonEmptyString(
		stringMapValue(labels, "listener_id"),
		stringMapValue(labels, "proxy_listener_id"),
		stringMapValue(labels, "egress_listener_id"),
	)
}

func stringMapValue(values map[string]any, key string) string {
	if len(values) == 0 {
		return ""
	}
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func (r *Runtime) writeProto(w http.ResponseWriter, message proto.Message) {
	data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func readRequestBody(req *http.Request) ([]byte, error) {
	defer req.Body.Close()
	return io.ReadAll(io.LimitReader(req.Body, 1<<20))
}

func protocolFromName(protocol string) proxyruntimev1.ProxyProtocol {
	switch protocol {
	case "socks5":
		return proxyruntimev1.ProxyProtocol_PROXY_PROTOCOL_SOCKS5
	default:
		return proxyruntimev1.ProxyProtocol_PROXY_PROTOCOL_HTTP
	}
}

func protocolName(protocol proxyruntimev1.ProxyProtocol) string {
	switch protocol {
	case proxyruntimev1.ProxyProtocol_PROXY_PROTOCOL_SOCKS5:
		return "socks5"
	default:
		return "http"
	}
}

func protocolFromURL(proxyURL *url.URL) proxyruntimev1.ProxyProtocol {
	if proxyURL != nil && proxyURL.Scheme == "socks5" {
		return proxyruntimev1.ProxyProtocol_PROXY_PROTOCOL_SOCKS5
	}
	return proxyruntimev1.ProxyProtocol_PROXY_PROTOCOL_HTTP
}

func portFromURL(proxyURL *url.URL) uint32 {
	portValue := proxyURL.Port()
	if portValue == "" {
		return 0
	}
	var port uint32
	_, _ = fmt.Sscanf(portValue, "%d", &port)
	return port
}

func providerHTTPProxyRef(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := provider.ParseProxy(raw, "http")
	if err != nil {
		return "configured"
	}
	return parsed.Scheme + "://" + parsed.Host
}
