package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestGateJournalRecoversWithoutRepeatingEffectsAndSeparatesClients(t *testing.T) {
	executor, root := testExecutor(t)
	defer executor.Close()
	executor.gateOperationDir = t.TempDir()
	call := func(method, client, key string, args map[string]any) map[string]any {
		t.Helper()
		params := map[string]any{"client_id": client, "agent_id": "agent", "key": key}
		if args != nil {
			params["name"] = "write_file"
			params["arguments"] = args
		}
		raw, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
		response, err := executor.callGateOperation(context.Background(), raw)
		if err != nil {
			t.Fatal(err)
		}
		var envelope map[string]any
		if err := json.Unmarshal(response, &envelope); err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	path := filepath.Join(root, "gate-once.txt")
	args := map[string]any{"path": path, "content": "first", "if_absent": true}
	first := call("bridge/operations/create", "one", "key", args)
	result, ok := first["result"].(map[string]any)
	if !ok || result["status"] != "completed" {
		t.Fatalf("create: %v", first)
	}
	if err := os.WriteFile(path, []byte("external change"), 0o600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			repeated := call("bridge/operations/create", "one", "key", args)
			if repeated["error"] != nil {
				t.Errorf("duplicate: %v", repeated)
			}
		}()
	}
	wg.Wait()
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "external change" {
		t.Fatalf("duplicate effect: %q %v", content, err)
	}
	changed := call("bridge/operations/create", "one", "key", map[string]any{"path": path, "content": "changed", "if_absent": true})
	if changed["error"] == nil {
		t.Fatal("changed payload accepted")
	}
	foreign := call("bridge/operations/lookup", "other-client", "key", nil)
	if foreign["result"].(map[string]any)["status"] != "not_found" {
		t.Fatalf("scope leaked: %v", foreign)
	}
	executor.gateOperations = sync.Map{}
	lookup := call("bridge/operations/lookup", "one", "key", nil)
	if lookup["result"].(map[string]any)["status"] != "completed" {
		t.Fatalf("restart lookup: %v", lookup)
	}
	if call("bridge/operations/lookup", "one", "lookup-key", args)["error"] == nil {
		t.Fatal("lookup accepted executable arguments")
	}
	foreignScope := commandHash(map[string]string{"source": "gate", "client": "other-client", "agent": "agent"})
	if _, err := os.Stat(filepath.Join(executor.gateOperationDir, foreignScope)); !os.IsNotExist(err) {
		t.Fatal("lookup created a journal directory")
	}
	if call("bridge/operations/delete", "one", "key", nil)["error"] == nil {
		t.Fatal("unknown operation method accepted")
	}
	executor.gateOperationDir = ""
	if call("bridge/operations/create", "one", "disabled", args)["error"] == nil {
		t.Fatal("disabled journal executed operation")
	}
}

func TestGateJournalPreviousOwnerKeepsUnknownOutcome(t *testing.T) {
	executor, _ := testExecutor(t)
	defer executor.Close()
	executor.gateOperationDir = t.TempDir()
	scope := commandHash(map[string]string{"source": "gate", "client": "one", "agent": "agent"})
	directory := filepath.Join(executor.gateOperationDir, scope)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	key := "interrupted"
	op := studioOperation{Key: key, ID: studioOperationID(key), Name: "write_file", Arguments: map[string]any{}, Owner: "previous-process", Scope: scope, Status: "running"}
	data, _ := json.Marshal(op)
	journal, _ := newStudioOperationsAt(directory)
	if err := os.WriteFile(journal.path(key), data, 0o600); err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "bridge/operations/lookup", "params": map[string]any{"client_id": "one", "agent_id": "agent", "key": key}})
	response, err := executor.callGateOperation(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Result struct {
			Status string `json:"status"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Result.Status != "outcome_unknown" {
		t.Fatalf("response %s", response)
	}
}
