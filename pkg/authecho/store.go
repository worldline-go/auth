package authecho

import (
	"sync"

	"github.com/gorilla/sessions"
)

type authStore struct {
	sessionFilesystem map[string]*sessions.FilesystemStore

	m sync.RWMutex
}

var Store = authStore{
	sessionFilesystem: make(map[string]*sessions.FilesystemStore),
}

func (s *authStore) AddSessionFilesystem(name string, store *sessions.FilesystemStore) {
	s.m.Lock()
	defer s.m.Unlock()

	s.sessionFilesystem[name] = store
}

func (s *authStore) GetSessionFilesystem(name string) *sessions.FilesystemStore {
	s.m.RLock()
	defer s.m.RUnlock()

	return s.sessionFilesystem[name]
}
