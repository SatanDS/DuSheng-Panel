package supervisor

import (
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

type Supervisor struct {
	gostPath string
	logger   *log.Logger

	mu         sync.Mutex
	cmd        *exec.Cmd
	done       chan error
	running    bool
	configPath string
}

func New(gostPath string, logger *log.Logger) *Supervisor {
	if logger == nil {
		logger = log.Default()
	}
	return &Supervisor{
		gostPath: strings.TrimSpace(gostPath),
		logger:   logger,
	}
}

func (s *Supervisor) Apply(ctx context.Context, configPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, ok := s.resolveGostPath()
	if !ok {
		s.logger.Printf("gost binary %q not found; skipping start", s.gostPath)
		return nil
	}

	if err := s.stopLocked(ctx); err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, path, "-C", configPath)
	cmd.Stdout = logWriter{s.logger, "gost stdout: "}
	cmd.Stderr = logWriter{s.logger, "gost stderr: "}
	if err := cmd.Start(); err != nil {
		return err
	}

	done := make(chan error, 1)
	s.cmd = cmd
	s.done = done
	s.running = true
	s.configPath = configPath
	s.logger.Printf("started gost pid=%d config=%s", cmd.Process.Pid, configPath)

	go s.wait(cmd, done)
	return nil
}

func (s *Supervisor) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopLocked(ctx)
}

func (s *Supervisor) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func (s *Supervisor) wait(cmd *exec.Cmd, done chan<- error) {
	err := cmd.Wait()
	done <- err
	close(done)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != cmd {
		return
	}
	s.cmd = nil
	s.done = nil
	s.running = false
	s.configPath = ""
	if err != nil {
		s.logger.Printf("gost exited: %v", err)
		return
	}
	s.logger.Printf("gost exited")
}

func (s *Supervisor) stopLocked(ctx context.Context) error {
	if s.cmd == nil || s.cmd.Process == nil {
		s.cmd = nil
		s.done = nil
		s.running = false
		return nil
	}

	cmd := s.cmd
	waitDone := s.done
	if waitDone == nil {
		s.cmd = nil
		s.running = false
		s.configPath = ""
		return nil
	}

	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-waitDone:
		s.logger.Printf("stopped gost")
		s.cmd = nil
		s.done = nil
		s.running = false
		s.configPath = ""
		return nil
	}
}

func (s *Supervisor) resolveGostPath() (string, bool) {
	if s.gostPath == "" {
		return "", false
	}
	if filepath.IsAbs(s.gostPath) || strings.ContainsAny(s.gostPath, `/\`) {
		info, err := os.Stat(s.gostPath)
		if err != nil || info.IsDir() {
			return "", false
		}
		return s.gostPath, true
	}
	path, err := exec.LookPath(s.gostPath)
	return path, err == nil
}

type logWriter struct {
	logger *log.Logger
	prefix string
}

func (w logWriter) Write(p []byte) (int, error) {
	text := strings.TrimSpace(string(p))
	if text != "" {
		w.logger.Printf("%s%s", w.prefix, text)
	}
	return len(p), nil
}
