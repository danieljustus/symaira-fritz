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
	mu      sync.RWMutex
	path    string
	Pins    map[string]string `json:"pins"`
	loadErr error
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
// Any read/parse error other than a missing file (which is a valid first-run state)
// is captured and returned via LoadError().
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

// Path returns the path of the pin store file.
func (ps *PinStore) Path() string {
	return ps.path
}

// LoadError returns any error encountered while loading the pin store from disk.
func (ps *PinStore) LoadError() error {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.loadErr
}

func (ps *PinStore) load() error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if ps.path == "" {
		return nil
	}
	data, err := os.ReadFile(ps.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			ps.loadErr = nil
			return nil
		}
		ps.loadErr = err
		return err
	}
	var stored struct {
		Pins map[string]string `json:"pins"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		ps.loadErr = fmt.Errorf("corrupt pin store JSON: %w", err)
		return ps.loadErr
	}
	if stored.Pins != nil {
		ps.Pins = stored.Pins
	}
	ps.loadErr = nil
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

// SetPin records and persists a pin for hostPort. If the store failed to load,
// SetPin refuses to overwrite the corrupt file and returns an error.
func (ps *PinStore) SetPin(hostPort, pin string) error {
	ps.mu.Lock()
	if ps.loadErr != nil {
		ps.mu.Unlock()
		return fmt.Errorf("cannot update corrupt pin store %s: %w", ps.path, ps.loadErr)
	}
	ps.Pins[hostPort] = pin
	ps.mu.Unlock()
	return ps.Save()
}

// ResetPin removes a pin for hostPort and saves the pin store.
// If the pin store was in an error state (e.g. corrupt JSON), ResetPin clears
// the error and writes a clean pin store.
func (ps *PinStore) ResetPin(hostPort string) (bool, error) {
	ps.mu.Lock()
	hadLoadErr := ps.loadErr != nil
	ps.loadErr = nil
	_, exists := ps.Pins[hostPort]
	if exists {
		delete(ps.Pins, hostPort)
	}
	ps.mu.Unlock()
	if !exists && !hadLoadErr {
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
