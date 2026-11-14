package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStudioOriginAndRuntime(t *testing.T) {
	if !studioNativeHostInvocation([]string{"agent", "chrome-extension://" + studioExtensionID + "/"}) {
		t.Fatal("known Studio origin was not selected")
	}
	if studioNativeHostInvocation([]string{"agent", "chrome-extension://other/"}) {
		t.Fatal("untrusted origin selected as Studio host")
	}
	e, _ := testExecutor(t)
	defer e.Close()
	h := &studioOperations{dir: t.TempDir()}
	init, err := handleStudioRequest(context.Background(), e, h, studioRequest{ID: "i", Method: "initialize", Params: map[string]any{"clientInfo": map[string]any{"name": "AI Studio", "version": "test"}}})
	if err != nil || init == nil {
		t.Fatalf("initialize: %v %v", init, err)
	}
	if init.(map[string]any)["studioOperations"].(map[string]any)["lookupByKey"] != true {
		t.Fatal("key lookup capability missing")
	}
	listed, err := handleStudioRequest(context.Background(), e, h, studioRequest{ID: "l", Method: "tools/list", Params: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(listed)
	if !json.Valid(b) {
		t.Fatal("invalid tools/list response")
	}
	toolNames := map[string]bool{}
	for _, tool := range listed.(map[string]any)["tools"].([]any) {
		if def, ok := tool.(map[string]any); ok {
			toolNames[def["name"].(string)] = true
		}
	}
	for _, name := range []string{"exec_command", "list_commands", "poll_command", "list_agents"} {
		if !toolNames[name] {
			t.Errorf("v5 tool missing: %s", name)
		}
	}
	call, err := handleStudioRequest(context.Background(), e, h, studioRequest{ID: "c", Method: "tools/call", Params: map[string]any{"name": "list_agents"}})
	if err != nil {
		t.Fatal(err)
	}
	if call.(map[string]any)["structuredContent"] == nil {
		t.Fatal("list_agents missing structured content")
	}
}

func TestStudioRootsRequireValidSavedSettings(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("HOME", dir)
	t.Setenv("WEBCODEX_ALLOWED_ROOTS", "")
	if roots := studioAllowedRoots(); len(roots) != 0 {
		t.Fatalf("missing settings granted access: %v", roots)
	}
	if err := os.MkdirAll(studioConfigDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(studioSettingsPath(), []byte("invalid JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	if roots := studioAllowedRoots(); len(roots) != 0 {
		t.Fatalf("invalid settings granted access: %v", roots)
	}
	data, _ := json.Marshal(studioSettings{ExtensionID: studioExtensionID, AllowedRoots: []string{dir}})
	if err := os.WriteFile(studioSettingsPath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if roots := studioAllowedRoots(); len(roots) != 1 || roots[0] != dir {
		t.Fatalf("saved roots were not restored: %v", roots)
	}
}

func TestStudioOperationIdempotencyAndRecovery(t *testing.T) {
	e, _ := testExecutor(t)
	defer e.Close()
	h := &studioOperations{dir: t.TempDir()}
	args := map[string]any{}
	one, err := h.create(context.Background(), e, "same", "list_allowed_roots", args, "")
	if err != nil {
		t.Fatal(err)
	}
	two, err := h.create(context.Background(), e, "same", "list_allowed_roots", args, "")
	if err != nil || two["operation_id"] != one["operation_id"] {
		t.Fatalf("duplicate did not return saved operation: %#v %v", two, err)
	}
	if _, err = h.create(context.Background(), e, "same", "delete_path", map[string]any{"path": "x"}, ""); err == nil {
		t.Fatal("mismatched duplicate accepted")
	}
	local, err := h.create(context.Background(), e, "agents", "list_agents", nil, "local")
	if err != nil || local["status"] != "completed" {
		t.Fatalf("list_agents operation failed: %#v %v", local, err)
	}
	op := studioOperation{Key: "crash", ID: studioOperationID("crash"), Name: "delete_path", Arguments: map[string]any{}, Status: "running"}
	data, _ := json.Marshal(op)
	sumPath := h.path(op.Key)
	if err = os.WriteFile(sumPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	restarted, err := newStudioOperationsAt(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.get(op.ID)
	if err != nil || got["status"] != "outcome_unknown" {
		t.Fatalf("crashed operation not recovered as unknown: %#v %v", got, err)
	}
	restarted.owner = op.Owner
	restarted.unconfirmed.Store(op.ID, true)
	got, err = restarted.get(op.ID)
	if err != nil || got["status"] != "outcome_unknown" {
		t.Fatalf("failed result persistence remained running: %#v %v", got, err)
	}
	_ = filepath.Base(sumPath)
}

func TestStudioChunkFramesStayWithinNativeLimit(t *testing.T) {
	data := map[string]any{"value": string(make([]byte, studioChunkBytes*4))}
	encoded, _ := json.Marshal(data)
	frames := new(testNativeFrames)
	if err := writeStudioResponse(frames, "id", data, nil); err != nil {
		t.Fatal(err)
	}
	for _, frame := range frames.frames {
		if len(frame) > browserBridgeMax {
			t.Fatalf("chunk frame too large: %d", len(frame))
		}
	}
	if len(encoded) == 0 || len(frames.frames) < 2 {
		t.Fatal("expected chunked response")
	}
}

func TestStudioLargeOperationResultPreservesContentAndStatus(t *testing.T) {
	op := studioOperation{ID: studioOperationID("large"), Status: "completed", Result: map[string]any{"text": string(make([]byte, 5<<20))}}
	result := studioOperationResult(op)
	if result["status"] != "completed" {
		t.Fatalf("status changed: %#v", result)
	}
	if result["result"].(map[string]any)["text"] != op.Result.(map[string]any)["text"] {
		t.Fatal("large result content changed")
	}
}

func TestStudioOperationLookupRejectsNonHexIDs(t *testing.T) {
	h := &studioOperations{dir: t.TempDir()}
	if _, err := h.get("op_" + strings.Repeat(".", 64)); err == nil {
		t.Fatal("accepted non-hex operation id")
	}
}

func TestStudioKeyLookupDoesNotExecuteAndPreservesCompletedEffect(t *testing.T) {
	e, root := testExecutor(t)
	h, _ := newStudioOperationsAt(t.TempDir())
	lookup := func(key string) map[string]any {
		t.Helper()
		value, err := handleStudioRequest(context.Background(), e, h, studioRequest{Method: "operations/lookup", Params: map[string]any{"key": key}})
		if err != nil {
			t.Fatal(err)
		}
		return value.(map[string]any)
	}
	if got := lookup("lost-response"); got["status"] != "not_found" {
		t.Fatalf("missing lookup: %v", got)
	}
	if files, _ := os.ReadDir(h.dir); len(files) != 0 {
		t.Fatal("lookup wrote a journal entry")
	}
	path := filepath.Join(root, "once.txt")
	args := map[string]any{"path": path, "content": "first", "if_absent": true}
	first, err := h.create(context.Background(), e, "lost-response", "write_file", args, "local")
	if err != nil || first["status"] != "completed" {
		t.Fatalf("create: %v %v", first, err)
	}
	if err := os.WriteFile(path, []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, _ = newStudioOperationsAt(h.dir)
	if got := lookup("lost-response"); got["status"] != "completed" || got["operation_id"] != first["operation_id"] {
		t.Fatalf("restart lookup: %v", got)
	}
	var requests sync.WaitGroup
	for range 12 {
		requests.Go(func() {
			result, err := h.create(context.Background(), e, "lost-response", "write_file", args, "local")
			if err != nil || result["status"] != "completed" {
				t.Errorf("duplicate: %v %v", result, err)
			}
		})
	}
	requests.Wait()
	if data, _ := os.ReadFile(path); string(data) != "after" {
		t.Fatal("recovery executed the write again")
	}
}

func TestStudioJournalScopeCorruptionAndExpiry(t *testing.T) {
	e, _ := testExecutor(t)
	h := &studioOperations{dir: t.TempDir(), owner: "owner", scope: "client-a"}
	key := "scoped"
	if _, err := h.create(context.Background(), e, key, "list_agents", nil, "local"); err != nil {
		t.Fatal(err)
	}
	other := *h
	other.scope = "client-b"
	if _, err := other.get(studioOperationID(key)); err == nil {
		t.Fatal("another client read the result")
	}
	if _, err := other.create(context.Background(), e, key, "list_agents", nil, "local"); err == nil {
		t.Fatal("another client reused the key")
	}
	for _, broken := range []string{"{", `{}`, `{"id":"wrong","status":"completed"}`} {
		if err := os.WriteFile(h.path(key), []byte(broken), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := h.get(studioOperationID(key))
		if err != nil || got["status"] != "outcome_unknown" {
			t.Fatalf("corruption: %v %v", got, err)
		}
	}
	old := fmt.Sprintf("%d-old", time.Now().Add(-25*time.Hour).UnixMilli())
	for range 2 {
		got, err := h.create(context.Background(), e, old, "list_agents", nil, "local")
		if err != nil || got["status"] != "expired" {
			t.Fatalf("expired key: %v %v", got, err)
		}
	}
	got, err := h.get(studioOperationID(old))
	if err != nil || got["status"] != "expired" {
		t.Fatalf("expired tombstone: %v %v", got, err)
	}
	legacy := studioOperation{Key: "legacy", ID: studioOperationID("legacy"), Name: "list_agents", Arguments: map[string]any{}, Status: "completed", Result: map[string]any{"content": []any{}}}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(h.path(legacy.Key), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := h.get(legacy.ID); err != nil || got["status"] != "completed" {
		t.Fatalf("legacy record: %v %v", got, err)
	}
}

func TestStudioConcurrentInitialReservation(t *testing.T) {
	e, root := testExecutor(t)
	h, _ := newStudioOperationsAt(t.TempDir())
	args := map[string]any{"path": filepath.Join(root, "once.txt"), "content": "once", "if_absent": true}
	var requests sync.WaitGroup
	for range 20 {
		requests.Go(func() {
			got, err := h.create(context.Background(), e, "concurrent", "write_file", args, "local")
			if err != nil || got["status"] != "running" && got["status"] != "completed" {
				t.Errorf("concurrent reservation: %v %v", got, err)
			}
		})
	}
	requests.Wait()
	got, err := h.get(studioOperationID("concurrent"))
	if err != nil || got["status"] != "completed" {
		t.Fatalf("final state: %v %v", got, err)
	}
}

type testNativeFrames struct{ frames [][]byte }

func (w *testNativeFrames) Write(p []byte) (int, error) {
	w.frames = append(w.frames, append([]byte(nil), p...))
	return len(p), nil
}
