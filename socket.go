package manager

import (
	"errors"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// attachSocket - Attaches the probe to the provided socket
func (p *Probe) attachSocket() error {
	sl, err := newSocketLink(p.SocketFD, p.program.FD())
	if err != nil {
		return err
	}
	p.progLink = sl
	return nil
}

func newSocketLink(sockFD int, progFD int) (*socketLink, error) {
	sl := &socketLink{
		sockFD: sockFD,
		progFD: progFD,
	}
	if err := sl.attach(); err != nil {
		return nil, err
	}
	return sl, nil
}

type socketLink struct {
	mtx      sync.Mutex
	attached bool
	sockFD   int
	progFD   int
}

func (s *socketLink) detach() error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if !s.attached {
		return nil
	}

	if err := syscall.SetsockoptInt(s.sockFD, syscall.SOL_SOCKET, unix.SO_DETACH_BPF, s.progFD); err != nil {
		if errors.Is(err, unix.ENOENT) {
			s.attached = false
		}
		return err
	}
	s.attached = false
	return nil
}

func (s *socketLink) attach() error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.attached {
		return nil
	}

	if err := syscall.SetsockoptInt(s.sockFD, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, s.progFD); err != nil {
		return err
	}
	s.attached = true
	return nil
}

func (s *socketLink) Close() error {
	return s.detach()
}

func (s *socketLink) Pause() error {
	return s.detach()
}

func (s *socketLink) Resume() error {
	return s.attach()
}
