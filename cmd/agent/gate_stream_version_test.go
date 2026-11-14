package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"webcodex/internal/buildinfo"
)

type idleRunner struct{}

func (idleRunner) call(context.Context, json.RawMessage) (json.RawMessage, error) { return nil, nil }

func TestStreamVersionWireAndLegacyReconnect(t *testing.T) {
	seen := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		if got := r.URL.Query().Get("version"); got != buildinfo.Version {
			t.Errorf("query version = %q", got)
		}
		if seen == 1 {
			w.Header().Set("X-WebCodex-Version", "gate-test")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	for i := 0; i < 2; i++ {
		if err := streamOnce(context.Background(), server.Client(), server.URL, "secret", idleRunner{}); err == nil {
			t.Fatal("closed test stream should report a reconnectable error")
		}
	}
	if seen != 2 {
		t.Fatalf("connections = %d, want 2", seen)
	}
}

func TestStreamAdvertisesGateJournalOnlyWhenConfigured(t *testing.T) {
	executor, _ := testExecutor(t)
	defer executor.Close()
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Query().Get("operations"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	_ = streamOnce(context.Background(), server.Client(), server.URL, "secret", executor)
	executor.gateOperationDir = t.TempDir()
	_ = streamOnce(context.Background(), server.Client(), server.URL, "secret", executor)
	if len(queries) != 2 || queries[0] != "" || queries[1] != "1" {
		t.Fatalf("capabilities: %v", queries)
	}
}
