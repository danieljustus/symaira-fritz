package fritz

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// PinStore manages trusted host public key pins (TOFU).
type PinStore struct {
	mu   sync.RWMutex
	path string
	Pins map[string]string `json:"pins"`
}

// DefaultPinStorePath returns the path to ~/.config/symfritz/pins.json.
func DefaultPinStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "symfritz", "pins.json")
}

// NewPinStore initializes a PinStore with the given path (or default path if empty).
func NewPinStore(path string) *PinStore {
	if path == "" {
		path = DefaultPinStorePath()
	}
	ps := &PinStore{
		path: path,
		Pins: make(map[string]string),
	}
	_ = ps.load()
	return ps
}

func (ps *PinStore) load() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.path == "" {
		return nil
	}
	data, err := os.ReadFile(ps.path)
	if err != nil {
		return err
	}
	var stored struct {
		Pins map[string]string `json:"pins"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		return err
	}
	if stored.Pins != nil {
		ps.Pins = stored.Pins
	}
	return nil
}

// Save writes the pin store to disk with mode 0600.
func (ps *PinStore) Save() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.path == "" {
		return errors.New("pin store path not configured")
	}
	dir := filepath.Dir(ps.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating pin store dir: %w", err)
	}
	data, err := json.MarshalIndent(struct {
		Pins map[string]string `json:"pins"`
	}{Pins: ps.Pins}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling pins: %w", err)
	}
	return os.WriteFile(ps.path, data, 0600)
}

// GetPin returns the recorded SPKI pin for hostPort, or empty string.
func (ps *PinStore) GetPin(hostPort string) string {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.Pins[hostPort]
}

// SetPin records and persists a pin for hostPort.
func (ps *PinStore) SetPin(hostPort, pin string) error {
	ps.mu.Lock()
	ps.Pins[hostPort] = pin
	ps.mu.Unlock()
	return ps.Save()
}

// ResetPin removes a pin for hostPort and saves the pin store.
func (ps *PinStore) ResetPin(hostPort string) (bool, error) {
	ps.mu.Lock()
	_, exists := ps.Pins[hostPort]
	if exists {
		delete(ps.Pins, hostPort)
	}
	ps.mu.Unlock()
	if !exists {
		return false, nil
	}
	err := ps.Save()
	return true, err
}

// CalculateSPKIPin computes base64(SHA-256(SPKI)) for a raw DER-encoded certificate.
func CalculateSPKIPin(rawCert []byte) (string, error) {
	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return "", fmt.Errorf("parsing certificate: %w", err)
	}
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}
