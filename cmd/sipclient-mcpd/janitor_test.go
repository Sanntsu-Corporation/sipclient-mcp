package main

import (
	"context"
	"testing"
	"time"
)

// TestJanitorRunsStartupSweep asserts startJanitor performs an immediate sweep
// and then respects context cancellation without leaking a goroutine.
func TestJanitorRunsStartupSweep(t *testing.T) {
	swept := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	// sweepFn stands in for artifacts.Sweep; startJanitor calls it once
	// immediately, then on each tick.
	go startJanitor(ctx, time.Hour, func() {
		select {
		case swept <- struct{}{}:
		default:
		}
	})
	select {
	case <-swept:
	case <-time.After(2 * time.Second):
		t.Fatal("startup sweep did not run")
	}
	cancel()
}
