package gost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type ManagerConfig struct {
	GostPath    string
	ConfigDir   string
	APIAddr     string
	MetricsAddr string
}

type Manager struct {
	cfg    ManagerConfig
	logger *slog.Logger

	mu      sync.Mutex
	current *process
}

type process struct {
	cmd        *exec.Cmd
	configPath string
	configData []byte
	done       chan error
	exited     bool
	exitErr    error
}

type Status struct {
	Running    bool
	ConfigPath string
	LastError  string
}

func NewManager(cfg ManagerConfig, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{cfg: cfg, logger: logger}
}

func (m *Manager) Reload(ctx context.Context, cfg Config) error {
	data, err := marshalConfig(cfg)
	if err != nil {
		return err
	}

	m.mu.Lock()
	current := m.current
	if current != nil && current.exited {
		m.current = nil
		current = nil
	}
	m.mu.Unlock()

	if current != nil {
		if bytes.Equal(current.configData, data) {
			return nil
		}
		if err := writeConfigData(current.configPath, data); err != nil {
			return err
		}
		if err := reloadProcess(current); err != nil {
			return err
		}
		m.mu.Lock()
		if m.current == current {
			current.configData = append(current.configData[:0], data...)
		}
		m.mu.Unlock()
		return waitForServices(ctx, cfg.Services, 3*time.Second)
	}

	configPath, err := m.writeConfigBytes(data)
	if err != nil {
		return err
	}

	proc, err := m.start(ctx, configPath)
	if err != nil {
		return err
	}
	proc.configData = append([]byte(nil), data...)
	m.mu.Lock()
	m.current = proc
	m.mu.Unlock()
	go m.observe(proc)
	if err := waitForServices(ctx, cfg.Services, 3*time.Second); err != nil {
		m.mu.Lock()
		if m.current == proc {
			m.current = nil
		}
		m.mu.Unlock()
		_ = stopProcess(proc, 5*time.Second)
		return err
	}
	return nil
}

func (m *Manager) Stop() {
	m.mu.Lock()
	current := m.current
	m.current = nil
	m.mu.Unlock()
	if current != nil {
		_ = stopProcess(current, 5*time.Second)
	}
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		return Status{}
	}
	status := Status{Running: !m.current.exited, ConfigPath: m.current.configPath}
	if m.current.exitErr != nil {
		status.LastError = m.current.exitErr.Error()
	}
	return status
}

func marshalConfig(cfg Config) ([]byte, error) {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal gost config: %w", err)
	}
	return data, nil
}

func (m *Manager) writeConfigBytes(data []byte) (string, error) {
	dir := m.cfg.ConfigDir
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "proxy-runtime")
	}
	path := filepath.Join(dir, "gost.json")
	return path, writeConfigData(path, data)
}

func writeConfigData(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create gost config dir: %w", err)
	}
	file, err := os.CreateTemp(dir, ".gost-*.json")
	if err != nil {
		return fmt.Errorf("create gost config file: %w", err)
	}
	tempPath := file.Name()
	defer func() {
		_ = os.Remove(tempPath)
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write gost config file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close gost config file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace gost config file: %w", err)
	}
	return nil
}

func (m *Manager) start(ctx context.Context, configPath string) (*process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	args := []string{"-C", configPath}
	if m.cfg.APIAddr != "" {
		args = append(args, "-api", m.cfg.APIAddr)
	}
	if m.cfg.MetricsAddr != "" {
		args = append(args, "-metrics", m.cfg.MetricsAddr)
	}
	cmd := exec.Command(m.cfg.GostPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start gost: %w", err)
	}
	return &process{cmd: cmd, configPath: configPath, done: make(chan error, 1)}, nil
}

func (m *Manager) observe(proc *process) {
	err := proc.cmd.Wait()
	proc.done <- err
	close(proc.done)

	m.mu.Lock()
	proc.exited = true
	proc.exitErr = err
	isCurrent := m.current == proc
	m.mu.Unlock()

	if isCurrent && err != nil && !errors.Is(err, context.Canceled) {
		m.logger.Warn("gost process exited", "error", err)
	}
}

func stopProcess(proc *process, timeout time.Duration) error {
	if proc.exited || proc.cmd.Process == nil {
		return nil
	}
	_ = proc.cmd.Process.Signal(syscall.SIGTERM)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-proc.done:
		return nil
	case <-timer.C:
		_ = proc.cmd.Process.Kill()
		<-proc.done
		return nil
	}
}

func reloadProcess(proc *process) error {
	if proc.exited || proc.cmd.Process == nil {
		return errors.New("gost process is not running")
	}
	if err := proc.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("reload gost: %w", err)
	}
	return nil
}

func waitForServices(ctx context.Context, services []Service, timeout time.Duration) error {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	targets := serviceListenTargets(services)
	if len(targets) == 0 {
		return nil
	}
	pending := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		pending[target] = struct{}{}
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		for target := range pending {
			conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(waitCtx, "tcp", target)
			if err != nil {
				continue
			}
			_ = conn.Close()
			delete(pending, target)
		}
		if len(pending) == 0 {
			return nil
		}
		select {
		case <-waitCtx.Done():
			for target := range pending {
				return fmt.Errorf("gost listener %s is not ready: %w", target, waitCtx.Err())
			}
			return waitCtx.Err()
		case <-ticker.C:
		}
	}
}

func serviceListenTargets(services []Service) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(services))
	for _, service := range services {
		target, ok := serviceListenTarget(service.Addr)
		if !ok {
			continue
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	return out
}

func serviceListenTarget(addr string) (string, bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return "", false
	}
	switch host {
	case "", "::", "0.0.0.0", "[::]":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), true
}
