package acmednschallenge

import "sync"

type challengeStore struct {
	mu       sync.RWMutex
	records  map[string][]string
	onChange func()
}

func newChallengeStore() *challengeStore {
	return &challengeStore{records: map[string][]string{}}
}

func (s *challengeStore) setOnChange(f func()) {
	s.mu.Lock()
	s.onChange = f
	s.mu.Unlock()
}

func (s *challengeStore) get(fqdn string) ([]string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.records[fqdn]
	if !ok {
		return nil, false
	}
	return append([]string(nil), v...), true
}

func (s *challengeStore) add(fqdn, value string) {
	s.mu.Lock()
	s.records[fqdn] = append(s.records[fqdn], value)
	s.mu.Unlock()
	s.fireChange()
}

func (s *challengeStore) remove(fqdn string) {
	s.mu.Lock()
	delete(s.records, fqdn)
	s.mu.Unlock()
	s.fireChange()
}

func (s *challengeStore) snapshot() map[string][]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]string, len(s.records))
	for k, v := range s.records {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func (s *challengeStore) replace(records map[string][]string) {
	if records == nil {
		records = map[string][]string{}
	}
	s.mu.Lock()
	s.records = records
	s.mu.Unlock()
}

func (s *challengeStore) isEmpty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records) == 0
}

func (s *challengeStore) fireChange() {
	s.mu.RLock()
	cb := s.onChange
	s.mu.RUnlock()
	if cb != nil {
		cb()
	}
}
