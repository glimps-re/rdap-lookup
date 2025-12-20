package bootstrap

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/metrics"
	"github.com/glimps-re/rdap-lookup/internal/validate"
)

// Service manages bootstrap data lifecycle including background refresh.
type Service struct {
	loader          *Loader
	resolver        *Resolver
	refreshInterval time.Duration
	logger          *slog.Logger
	metrics         *metrics.Metrics

	// SSRF protection: validator to update on bootstrap refresh
	serverValidator *validate.RDAPServerValidator

	mu          sync.RWMutex
	stopCh      chan struct{}
	doneCh      chan struct{}
	running     bool
	staleLogged atomic.Bool // Prevent log spam for staleness warnings
}

// NewService creates a new bootstrap service.
func NewService(
	refreshInterval time.Duration,
	fetchTimeout time.Duration,
	logger *slog.Logger,
	m *metrics.Metrics,
) *Service {
	return &Service{
		loader:          NewLoader(fetchTimeout),
		refreshInterval: refreshInterval,
		logger:          logger,
		metrics:         m,
		stopCh:          make(chan struct{}),
		doneCh:          make(chan struct{}),
	}
}

// Start initializes the bootstrap data and starts the background refresh goroutine.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()

	// Initial load
	s.logger.Info("loading initial bootstrap data")
	if err := s.refresh(ctx); err != nil {
		return err
	}

	// Start background refresh (uses its own context for periodic refreshes)
	go s.backgroundRefresh(ctx)

	return nil
}

// Stop stops the background refresh goroutine.
func (s *Service) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	s.mu.Unlock()

	close(s.stopCh)
	<-s.doneCh
}

// Resolver returns the resolver for RDAP URL lookups.
func (s *Service) Resolver() *Resolver {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.resolver
}

// IsReady returns true if bootstrap data has been loaded.
func (s *Service) IsReady() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.resolver != nil
}

// SetServerValidator sets the SSRF validator to update on bootstrap refresh.
func (s *Service) SetServerValidator(v *validate.RDAPServerValidator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serverValidator = v
}

// refresh loads all bootstrap data.
func (s *Service) refresh(ctx context.Context) error {
	start := time.Now()

	bootstrap, err := s.loader.LoadAll(ctx)
	if err != nil {
		s.logger.Error("failed to load bootstrap data",
			slog.String("error", err.Error()),
		)
		if s.metrics != nil {
			s.metrics.BootstrapRefreshErrors.Inc()
		}
		return err
	}

	s.mu.Lock()
	s.resolver = NewResolver(bootstrap)
	validator := s.serverValidator
	s.mu.Unlock()

	duration := time.Since(start)

	// Update SSRF allowlist if validator is set
	if validator != nil {
		servers := s.resolver.GetAllRDAPServers()
		validator.UpdateAllowlist(servers)
		s.logger.Debug("updated SSRF allowlist",
			slog.Int("server_count", len(servers)),
		)
		// Reset stale warning flag after successful update
		s.staleLogged.Store(false)
	}

	// Update metrics
	if s.metrics != nil {
		s.metrics.BootstrapLastRefresh.Set(float64(time.Now().Unix()))
		s.metrics.BootstrapTLDsLoaded.Set(float64(bootstrap.DNS.TLDCount()))
	}

	s.logger.Info("bootstrap data loaded",
		slog.Int("tlds", bootstrap.DNS.TLDCount()),
		slog.Int("ipv4_prefixes", bootstrap.IPv4.PrefixCount()),
		slog.Int("ipv6_prefixes", bootstrap.IPv6.PrefixCount()),
		slog.Int("asn_ranges", bootstrap.ASN.RangeCount()),
		slog.Duration("duration", duration),
	)

	return nil
}

// backgroundRefresh periodically refreshes bootstrap data.
// The passed context is used as a parent for refresh operations.
func (s *Service) backgroundRefresh(parentCtx context.Context) {
	defer close(s.doneCh)

	ticker := time.NewTicker(s.refreshInterval)
	stalenessTicker := time.NewTicker(1 * time.Minute) // Check staleness every minute
	defer ticker.Stop()
	defer stalenessTicker.Stop()

	for {
		select {
		case <-s.stopCh:
			s.logger.Info("stopping bootstrap refresh")
			return
		case <-parentCtx.Done():
			s.logger.Info("parent context cancelled, stopping bootstrap refresh")
			return
		case <-stalenessTicker.C:
			s.checkStaleness()
		case <-ticker.C:
			s.logger.Debug("refreshing bootstrap data")
			refreshCtx, cancel := context.WithTimeout(parentCtx, 60*time.Second)
			if err := s.refresh(refreshCtx); err != nil {
				s.logger.Warn("bootstrap refresh failed, using cached data",
					slog.String("error", err.Error()),
				)
			}
			cancel()
		}
	}
}

// checkStaleness checks if the SSRF allowlist is stale and updates metrics.
func (s *Service) checkStaleness() {
	s.mu.RLock()
	validator := s.serverValidator
	s.mu.RUnlock()

	if validator == nil || s.metrics == nil {
		return
	}

	age := validator.StalenessAge()
	s.metrics.SSRFAllowlistAge.Set(age.Seconds())

	// Staleness threshold is 2x the refresh interval
	threshold := s.refreshInterval * 2
	if validator.IsStale(threshold) {
		s.metrics.SSRFAllowlistStale.Set(1)
		// Only log warning once to prevent log spam
		if !s.staleLogged.Load() {
			s.staleLogged.Store(true)
			s.logger.Warn("SSRF allowlist is stale",
				slog.Duration("age", age),
				slog.Duration("threshold", threshold),
			)
		}
	} else {
		s.metrics.SSRFAllowlistStale.Set(0)
	}
}
