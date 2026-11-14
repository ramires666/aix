package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
	"webcodex/internal/protocol"
)

func TestBridgeOperationLookupByKeyIsReadOnlyAndScoped(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()
	ctx := context.Background()
	if err := srv.store.initBridgeOperations(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"lookup-owner", "lookup-other"} {
		if err := createTestAgent(srv.store, ctx, Agent{ID: id, Name: id, Enabled: true, AgentTokenHash: hashSecret(id)}, id, ""); err != nil {
			t.Fatal(err)
		}
		if err := srv.store.CreateAccessToken(ctx, AccessToken{TokenHash: hashSecret(id + "-token"), ClientID: id, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	key := fmt.Sprintf("%d-550e8400-e29b-41d4-a716-446655440000", time.Now().UnixMilli())
	op, err := srv.store.acceptBridgeOperation(ctx, "lookup-owner", bridgeOperationRequest{Key: key, Name: "read_file", AgentID: "lookup-owner", Arguments: map[string]any{"path": "fixture"}}, "hash", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(client, key string) (int, map[string]any) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/bridge/v1/operations/by-key?key="+url.QueryEscape(key), nil)
		r.Header.Set("Authorization", "Bearer "+client+"-token")
		w := httptest.NewRecorder()
		srv.handleBridgeGetOperation(w, r)
		var value map[string]any
		if w.Code == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
				t.Fatal(err)
			}
		}
		return w.Code, value
	}
	code, value := lookup("lookup-owner", key)
	if code != 200 || value["id"] != op.ID || value["status"] != "accepted" {
		t.Fatalf("owner lookup %d %v", code, value)
	}
	code, value = lookup("lookup-other", key)
	if code != 200 || value["status"] != "not_found" || value["id"] != nil {
		t.Fatalf("foreign lookup %d %v", code, value)
	}
	oldKey := fmt.Sprintf("%d-550e8400-e29b-41d4-a716-446655440001", time.Now().Add(-time.Hour).UnixMilli())
	code, value = lookup("lookup-owner", oldKey)
	if code != 200 || value["status"] != "expired" {
		t.Fatalf("expired lookup %d %v", code, value)
	}
	code, _ = lookup("lookup-owner", "invalid")
	if code != http.StatusBadRequest {
		t.Fatalf("invalid key status %d", code)
	}
	var count int
	var status string
	if err := srv.store.db.QueryRow(`SELECT COUNT(*) FROM bridge_operations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.db.QueryRow(`SELECT status FROM bridge_operations WHERE id=?`, op.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if count != 1 || status != "accepted" || len(srv.runtimeFor("lookup-owner").queue) != 0 {
		t.Fatalf("lookup mutated operation count=%d status=%s", count, status)
	}
	if _, err := srv.store.db.Exec(`UPDATE agents SET enabled=0 WHERE id='lookup-owner'`); err != nil {
		t.Fatal(err)
	}
	code, _ = lookup("lookup-owner", key)
	if code != http.StatusForbidden {
		t.Fatalf("revoked agent status %d", code)
	}
}

func TestBridgeOperationAcceptanceIsIdempotentAndConflictsOnChangedArgs(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()
	ctx := context.Background()
	if err := srv.store.initBridgeOperations(ctx); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.CreateAgent(ctx, Agent{ID: "op-agent", Name: "Agent", Enabled: true, AgentTokenHash: hashSecret("agent")}); err != nil {
		t.Fatal(err)
	}
	req := bridgeOperationRequest{Key: fmt.Sprintf("%d-550e8400-e29b-41d4-a716-446655440000", time.Now().UnixMilli()), Name: "read_file", AgentID: "op-agent", Arguments: map[string]any{"path": "readme"}}
	canonical, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "tools/call", "params": map[string]any{"name": "read_file", "arguments": map[string]any{"path": "readme", "agent_id": "op-agent"}}})
	digest := sha256.Sum256(canonical)
	if err := srv.store.CreateMCPClient(ctx, MCPClient{ID: "op-client", Name: "Client", Enabled: true, OAuthClientID: "op-oauth", OAuthClientSecretHash: hashSecret("secret")}); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.SetMCPAgents(ctx, "op-client", []string{"op-agent"}); err != nil {
		t.Fatal(err)
	}
	first, err := srv.store.acceptBridgeOperation(ctx, "op-client", req, hex.EncodeToString(digest[:]), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := srv.store.acceptBridgeOperation(ctx, "op-client", req, hex.EncodeToString(digest[:]), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || first.Status != "accepted" || second.Status != "accepted" {
		t.Fatalf("not idempotent: first=%+v second=%+v", first, second)
	}
	var legacyArgs []byte
	if err := srv.store.db.QueryRowContext(ctx, `SELECT args_json FROM bridge_operations WHERE id=?`, first.ID).Scan(&legacyArgs); err != nil || legacyArgs != nil {
		t.Fatalf("legacy operation unexpectedly persisted arguments: bytes=%d error=%v", len(legacyArgs), err)
	}
	if _, err = srv.store.acceptBridgeOperation(ctx, "op-client", req, "different", time.Now()); !errors.Is(err, errBridgeOperationConflict) {
		t.Fatalf("changed arguments error = %v", err)
	}
	if _, err = srv.store.acceptBridgeOperation(ctx, "other-client", req, hex.EncodeToString(digest[:]), time.Now()); err == nil {
		t.Fatal("foreign client unexpectedly accepted without an MCP client")
	}
}

func TestBridgeOperationRestartMarksInFlightUnknown(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()
	ctx := context.Background()
	if err := srv.store.initBridgeOperations(ctx); err != nil {
		t.Fatal(err)
	}
	if err := createTestAgent(srv.store, ctx, Agent{ID: "restart-client", Name: "Agent", Enabled: true, AgentTokenHash: hashSecret("agent")}, "restart-client", ""); err != nil {
		t.Fatal(err)
	}
	_, err := srv.store.db.ExecContext(ctx, `INSERT INTO bridge_operations(id,client_id,key,name,agent_id,args_hash,status,created_at,expires_at) VALUES('op','restart-client','1-550e8400-e29b-41d4-a716-446655440000','read_file','restart-client','hash','dispatching',?,?)`, time.Now().Format(time.RFC3339Nano), time.Now().Add(time.Hour).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	if err = srv.store.initBridgeOperations(ctx); err != nil {
		t.Fatal(err)
	}
	var status string
	if err = srv.store.db.QueryRowContext(ctx, `SELECT status FROM bridge_operations WHERE id='op'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "outcome_unknown" {
		t.Fatalf("status=%q", status)
	}
}

func TestBridgeOperationDurableIntentSurvivesRestart(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()
	ctx := context.Background()
	if err := srv.store.initBridgeOperations(ctx); err != nil {
		t.Fatal(err)
	}
	if err := createTestAgent(srv.store, ctx, Agent{ID: "durable-agent", Name: "Agent", Enabled: true, AgentTokenHash: hashSecret("agent")}, "durable-agent", ""); err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("%d-550e8400-e29b-41d4-a716-446655440000", time.Now().UnixMilli())
	op, err := srv.store.acceptBridgeOperation(ctx, "durable-agent", bridgeOperationRequest{Key: key, Name: "write_file", AgentID: "durable-agent", Arguments: map[string]any{"path": "fixture", "content": "exact"}}, "hash", time.Now(), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = srv.store.db.ExecContext(ctx, `UPDATE bridge_operations SET status='dispatching' WHERE id=?`, op.ID); err != nil {
		t.Fatal(err)
	}
	if err = srv.store.initBridgeOperations(ctx); err != nil {
		t.Fatal(err)
	}
	var status string
	var args []byte
	var durable bool
	if err = srv.store.db.QueryRowContext(ctx, `SELECT status,args_json,durable FROM bridge_operations WHERE id=?`, op.ID).Scan(&status, &args, &durable); err != nil {
		t.Fatal(err)
	}
	if status != "dispatching" || !durable || !bytes.Contains(args, []byte(`"content":"exact"`)) {
		t.Fatalf("intent lost: status=%s durable=%t args=%s", status, durable, args)
	}
}

func TestBridgeOperationDurableRecoveryUsesAgentLookup(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()
	ctx := context.Background()
	if err := srv.store.initBridgeOperations(ctx); err != nil {
		t.Fatal(err)
	}
	if err := createTestAgent(srv.store, ctx, Agent{ID: "durable-agent", Name: "Agent", Enabled: true, AgentTokenHash: hashSecret("agent"), AllowedTools: "write_file"}, "durable-agent", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.CreateAccessToken(ctx, AccessToken{TokenHash: hashSecret("durable-token"), ClientID: "durable-agent", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("%d-550e8400-e29b-41d4-a716-446655440000", time.Now().UnixMilli())
	op, err := srv.store.acceptBridgeOperation(ctx, "durable-agent", bridgeOperationRequest{Key: key, Name: "write_file", AgentID: "durable-agent", Arguments: map[string]any{"path": "fixture", "content": "exact"}}, "hash", time.Now(), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = srv.store.db.ExecContext(ctx, `UPDATE bridge_operations SET status='dispatching' WHERE id=?`, op.ID); err != nil {
		t.Fatal(err)
	}
	if err = srv.store.initBridgeOperations(ctx); err != nil {
		t.Fatal(err)
	}
	rt := srv.runtimeFor("durable-agent")
	_, stream, _ := rt.activateAgentStreamWithOperations(ctx, true)
	defer rt.deactivateAgentStream(stream)
	completed := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest(http.MethodGet, "/bridge/v1/operations/"+op.ID, nil)
		r.Header.Set("Authorization", "Bearer durable-token")
		w := httptest.NewRecorder()
		srv.handleBridgeGetOperation(w, r)
		completed <- w
	}()
	call := <-rt.queue
	var message struct {
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(call.Request, &message); err != nil {
		t.Fatal(err)
	}
	if message.Method != "bridge/operations/lookup" || message.Params["key"] != key || message.Params["client_id"] != "durable-agent" || message.Params["agent_id"] != "durable-agent" {
		t.Fatalf("unsafe recovery call: %s", call.Request)
	}
	identity := sha256.Sum256([]byte(key))
	response, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": op.ID, "result": map[string]any{"status": "completed", "operation_id": "op_" + hex.EncodeToString(identity[:]), "result": map[string]any{"isError": false, "structuredContent": map[string]any{"path": "fixture"}}}})
	rt.mu.Lock()
	pending := rt.pending[call.ID]
	rt.mu.Unlock()
	pending <- protocol.AgentResponse{ID: call.ID, Response: response}
	w := <-completed
	if w.Code != 200 {
		t.Fatalf("get status=%d body=%s", w.Code, w.Body.String())
	}
	var got bridgeOperation
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != op.ID || got.Status != "completed" || !bytes.Contains(got.Result, []byte(`"path":"fixture"`)) || len(rt.queue) != 0 {
		t.Fatalf("recovery mismatch: %+v queue=%d", got, len(rt.queue))
	}
}

func TestBridgeOperationDurableNotFoundRecreatesOnlySavedIntent(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()
	ctx := context.Background()
	if err := srv.store.initBridgeOperations(ctx); err != nil {
		t.Fatal(err)
	}
	if err := createTestAgent(srv.store, ctx, Agent{ID: "retry-agent", Name: "Agent", Enabled: true, AgentTokenHash: hashSecret("agent"), AllowedTools: "write_file"}, "retry-agent", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.CreateAccessToken(ctx, AccessToken{TokenHash: hashSecret("retry-token"), ClientID: "retry-agent", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("%d-550e8400-e29b-41d4-a716-446655440000", time.Now().UnixMilli())
	arguments := map[string]any{"path": "fixture", "content": "saved", "if_absent": true}
	canonical, _ := json.Marshal(map[string]any{"name": "write_file", "agent_id": "retry-agent", "arguments": arguments})
	digest := sha256.Sum256(canonical)
	op, err := srv.store.acceptBridgeOperation(ctx, "retry-agent", bridgeOperationRequest{Key: key, Name: "write_file", AgentID: "retry-agent", Arguments: arguments}, hex.EncodeToString(digest[:]), time.Now(), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = srv.store.db.ExecContext(ctx, `UPDATE bridge_operations SET status='dispatching' WHERE id=?`, op.ID); err != nil {
		t.Fatal(err)
	}
	rt := srv.runtimeFor("retry-agent")
	_, stream, _ := rt.activateAgentStreamWithOperations(ctx, true)
	defer rt.deactivateAgentStream(stream)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest(http.MethodGet, "/bridge/v1/operations/"+op.ID, nil)
		r.Header.Set("Authorization", "Bearer retry-token")
		w := httptest.NewRecorder()
		srv.handleBridgeGetOperation(w, r)
		done <- w
	}()
	respond := func(call protocol.AgentRequest, status string) {
		t.Helper()
		identity := sha256.Sum256([]byte(key))
		response, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": op.ID, "result": map[string]any{"status": status, "operation_id": "op_" + hex.EncodeToString(identity[:]), "result": map[string]any{"isError": false, "structuredContent": map[string]any{"bytes_written": 5}}}})
		rt.mu.Lock()
		pending := rt.pending[call.ID]
		rt.mu.Unlock()
		if pending == nil {
			t.Fatal("missing pending agent request")
		}
		pending <- protocol.AgentResponse{ID: call.ID, Response: response}
	}
	first := <-rt.queue
	var firstCall struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(first.Request, &firstCall)
	if firstCall.Method != "bridge/operations/lookup" {
		t.Fatalf("first method %s", firstCall.Method)
	}
	respond(first, "not_found")
	w := <-done
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"status":"not_found"`)) || !bytes.Contains(w.Body.Bytes(), []byte(op.ID)) || len(rt.queue) != 0 {
		t.Fatalf("GET dispatched mutation: status=%d body=%s queue=%d", w.Code, w.Body.String(), len(rt.queue))
	}
	requestBody, _ := json.Marshal(bridgeOperationRequest{Key: key, Name: "write_file", AgentID: "retry-agent", Arguments: arguments})
	post := httptest.NewRequest(http.MethodPost, "/bridge/v1/operations", bytes.NewReader(requestBody))
	post.Header.Set("Authorization", "Bearer retry-token")
	posted := httptest.NewRecorder()
	srv.handleBridgeCreateOperation(posted, post)
	if posted.Code != http.StatusAccepted {
		t.Fatalf("retry POST %d %s", posted.Code, posted.Body.String())
	}
	recheck := <-rt.queue
	var recheckCall struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(recheck.Request, &recheckCall)
	if recheckCall.Method != "bridge/operations/lookup" {
		t.Fatalf("POST did not check journal: %s", recheck.Request)
	}
	respond(recheck, "not_found")
	second := <-rt.queue
	var create struct {
		Method string `json:"method"`
		Params struct {
			Key       string         `json:"key"`
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(second.Request, &create); err != nil {
		t.Fatal(err)
	}
	if create.Method != "bridge/operations/create" || create.Params.Key != key || create.Params.Name != "write_file" || create.Params.Arguments["content"] != "saved" || create.Params.Arguments["path"] != "fixture" || create.Params.Arguments["if_absent"] != true {
		t.Fatalf("changed intent: %s", second.Request)
	}
	respond(second, "completed")
	deadline := time.Now().Add(time.Second)
	var status string
	for time.Now().Before(deadline) {
		_ = srv.store.db.QueryRowContext(ctx, `SELECT status FROM bridge_operations WHERE id=?`, op.ID).Scan(&status)
		if status == "completed" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if status != "completed" {
		t.Fatalf("POST recovery status=%s", status)
	}
}

func TestBridgeOperationOldAgentNeverGetsJournalMethod(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()
	ctx := context.Background()
	if err := srv.store.initBridgeOperations(ctx); err != nil {
		t.Fatal(err)
	}
	if err := createTestAgent(srv.store, ctx, Agent{ID: "old-agent", Name: "Agent", Enabled: true, AgentTokenHash: hashSecret("agent"), AllowedTools: "write_file"}, "old-agent", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.CreateAccessToken(ctx, AccessToken{TokenHash: hashSecret("old-token"), ClientID: "old-agent", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("%d-550e8400-e29b-41d4-a716-446655440000", time.Now().UnixMilli())
	op, err := srv.store.acceptBridgeOperation(ctx, "old-agent", bridgeOperationRequest{Key: key, Name: "write_file", AgentID: "old-agent", Arguments: map[string]any{"path": "fixture", "content": "saved"}}, "hash", time.Now(), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = srv.store.db.ExecContext(ctx, `UPDATE bridge_operations SET status='dispatching' WHERE id=?`, op.ID); err != nil {
		t.Fatal(err)
	}
	rt := srv.runtimeFor("old-agent")
	_, stream, _ := rt.activateAgentStream(ctx)
	defer rt.deactivateAgentStream(stream)
	r := httptest.NewRequest(http.MethodGet, "/bridge/v1/operations/"+op.ID, nil)
	r.Header.Set("Authorization", "Bearer old-token")
	w := httptest.NewRecorder()
	srv.handleBridgeGetOperation(w, r)
	if w.Code != 200 || len(rt.queue) != 0 {
		t.Fatalf("old agent received journal request: status=%d queued=%d", w.Code, len(rt.queue))
	}
}

func TestBridgeOperationChangedStoredArgumentsBlockReplay(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()
	ctx := context.Background()
	if err := srv.store.initBridgeOperations(ctx); err != nil {
		t.Fatal(err)
	}
	if err := createTestAgent(srv.store, ctx, Agent{ID: "hash-agent", Name: "Agent", Enabled: true, AgentTokenHash: hashSecret("agent"), AllowedTools: "write_file"}, "hash-agent", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.CreateAccessToken(ctx, AccessToken{TokenHash: hashSecret("hash-token"), ClientID: "hash-agent", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("%d-550e8400-e29b-41d4-a716-446655440000", time.Now().UnixMilli())
	op, err := srv.store.acceptBridgeOperation(ctx, "hash-agent", bridgeOperationRequest{Key: key, Name: "write_file", AgentID: "hash-agent", Arguments: map[string]any{"path": "fixture", "content": "safe"}}, "unmatching-hash", time.Now(), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = srv.store.db.ExecContext(ctx, `UPDATE bridge_operations SET status='dispatching' WHERE id=?`, op.ID); err != nil {
		t.Fatal(err)
	}
	rt := srv.runtimeFor("hash-agent")
	_, stream, _ := rt.activateAgentStreamWithOperations(ctx, true)
	defer rt.deactivateAgentStream(stream)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest(http.MethodGet, "/bridge/v1/operations/"+op.ID, nil)
		r.Header.Set("Authorization", "Bearer hash-token")
		w := httptest.NewRecorder()
		srv.handleBridgeGetOperation(w, r)
		done <- w
	}()
	call := <-rt.queue
	var message struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(call.Request, &message)
	if message.Method != "bridge/operations/lookup" {
		t.Fatalf("unexpected call %s", call.Request)
	}
	response, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": op.ID, "result": map[string]any{"status": "not_found"}})
	rt.mu.Lock()
	pending := rt.pending[call.ID]
	rt.mu.Unlock()
	pending <- protocol.AgentResponse{ID: call.ID, Response: response}
	w := <-done
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"status":"not_found"`)) || len(rt.queue) != 0 {
		t.Fatalf("GET dispatched corrupt intent: status=%d body=%s queue=%d", w.Code, w.Body.String(), len(rt.queue))
	}
	requestBody, _ := json.Marshal(bridgeOperationRequest{Key: key, Name: "write_file", AgentID: "hash-agent", Arguments: map[string]any{"path": "fixture", "content": "safe"}})
	post := httptest.NewRequest(http.MethodPost, "/bridge/v1/operations", bytes.NewReader(requestBody))
	post.Header.Set("Authorization", "Bearer hash-token")
	posted := httptest.NewRecorder()
	srv.handleBridgeCreateOperation(posted, post)
	if posted.Code != http.StatusConflict || len(rt.queue) != 0 {
		t.Fatalf("corrupt intent replayed: status=%d queue=%d", posted.Code, len(rt.queue))
	}
}

func TestBridgeOperationRejectsMismatchedJournalIdentityAndMissingResult(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		wrongID, missingResult bool
	}{{"wrong-id", true, false}, {"null-result", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			srv, cleanup := setupTestServer(t)
			defer cleanup()
			ctx := context.Background()
			if err := srv.store.initBridgeOperations(ctx); err != nil {
				t.Fatal(err)
			}
			if err := createTestAgent(srv.store, ctx, Agent{ID: "identity-agent", Name: "Agent", Enabled: true, AgentTokenHash: hashSecret("agent"), AllowedTools: "read_file"}, "identity-agent", ""); err != nil {
				t.Fatal(err)
			}
			if err := srv.store.CreateAccessToken(ctx, AccessToken{TokenHash: hashSecret("identity-token"), ClientID: "identity-agent", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			key := fmt.Sprintf("%d-550e8400-e29b-41d4-a716-446655440000", time.Now().UnixMilli())
			op, err := srv.store.acceptBridgeOperation(ctx, "identity-agent", bridgeOperationRequest{Key: key, Name: "read_file", AgentID: "identity-agent", Arguments: map[string]any{"path": "fixture"}}, "hash", time.Now(), true)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = srv.store.db.ExecContext(ctx, `UPDATE bridge_operations SET status='dispatching' WHERE id=?`, op.ID); err != nil {
				t.Fatal(err)
			}
			rt := srv.runtimeFor("identity-agent")
			_, stream, _ := rt.activateAgentStreamWithOperations(ctx, true)
			defer rt.deactivateAgentStream(stream)
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				r := httptest.NewRequest(http.MethodGet, "/bridge/v1/operations/"+op.ID, nil)
				r.Header.Set("Authorization", "Bearer identity-token")
				w := httptest.NewRecorder()
				srv.handleBridgeGetOperation(w, r)
				done <- w
			}()
			call := <-rt.queue
			identity := sha256.Sum256([]byte(key))
			agentID := "op_" + hex.EncodeToString(identity[:])
			if tc.wrongID {
				agentID = "op_other"
			}
			var result any = map[string]any{"isError": false, "structuredContent": map[string]any{"content": "safe"}}
			if tc.missingResult {
				result = nil
			}
			response, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": op.ID, "result": map[string]any{"status": "completed", "operation_id": agentID, "result": result}})
			rt.mu.Lock()
			pending := rt.pending[call.ID]
			rt.mu.Unlock()
			pending <- protocol.AgentResponse{ID: call.ID, Response: response}
			w := <-done
			if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"status":"outcome_unknown"`)) || bytes.Contains(w.Body.Bytes(), []byte(`"content":"safe"`)) {
				t.Fatalf("invalid agent result was delivered: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestBridgeOperationClaimDispatchesOnlyOnce(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()
	ctx := context.Background()
	if err := srv.store.initBridgeOperations(ctx); err != nil {
		t.Fatal(err)
	}
	if err := createTestAgent(srv.store, ctx, Agent{ID: "claim-agent", Name: "Agent", Enabled: true, AgentTokenHash: hashSecret("agent")}, "claim-agent", ""); err != nil {
		t.Fatal(err)
	}
	_, err := srv.store.db.ExecContext(ctx, `INSERT INTO bridge_operations(id,client_id,key,name,agent_id,args_hash,status,created_at,expires_at) VALUES('claim-op','claim-agent','1-550e8400-e29b-41d4-a716-446655440000','read_file','claim-agent','hash','accepted',?,?)`, time.Now().Format(time.RFC3339Nano), time.Now().Add(time.Hour).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	claimed := make(chan bool, 16)
	for i := 0; i < cap(claimed); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, e := srv.store.claimBridgeOperation(ctx, "claim-op")
			if e != nil {
				t.Errorf("claim: %v", e)
			}
			claimed <- ok
		}()
	}
	wg.Wait()
	close(claimed)
	n := 0
	for ok := range claimed {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("successful claims=%d, want 1", n)
	}
}

func TestBridgeOperationConcurrentCreateIsIdempotent(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()
	ctx := context.Background()
	if err := srv.store.initBridgeOperations(ctx); err != nil {
		t.Fatal(err)
	}
	if err := createTestAgent(srv.store, ctx, Agent{ID: "http-op-agent", Name: "Agent", Enabled: true, AgentTokenHash: hashSecret("agent")}, "http-op-agent", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.CreateAccessToken(ctx, AccessToken{TokenHash: hashSecret("http-op-token"), ClientID: "http-op-agent", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	body := []byte(fmt.Sprintf(`{"key":"%d-550e8400-e29b-41d4-a716-446655440000","name":"list_agents","agent_id":"http-op-agent","arguments":{}}`, time.Now().UnixMilli()))
	const callers = 12
	ops := make(chan bridgeOperation, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/bridge/v1/operations", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer http-op-token")
			rec := httptest.NewRecorder()
			srv.handleBridgeCreateOperation(rec, req)
			if rec.Code != http.StatusAccepted {
				t.Errorf("status=%d body=%s", rec.Code, rec.Body.String())
				return
			}
			var op bridgeOperation
			if err := json.Unmarshal(rec.Body.Bytes(), &op); err != nil {
				t.Errorf("decode: %v", err)
				return
			}
			ops <- op
		}()
	}
	wg.Wait()
	close(ops)
	var first string
	for op := range ops {
		id := op.ID
		if first == "" {
			first = id
		}
		if id != first {
			t.Fatalf("duplicate request returned IDs %q and %q", first, id)
		}
		if op.Status == "completed" && len(op.Result) == 0 {
			t.Fatalf("terminal concurrent POST omitted result for %s", id)
		}
	}
	var count int
	if err := srv.store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bridge_operations WHERE client_id='http-op-agent'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("stored operations=%d, want 1", count)
	}
	var status string
	var result []byte
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = srv.store.db.QueryRowContext(ctx, `SELECT status,result FROM bridge_operations WHERE id=?`, first).Scan(&status, &result)
		if status == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if status != "completed" {
		t.Fatalf("list_agents operation status=%q", status)
	}
	var response struct {
		StructuredContent struct {
			Agents []struct {
				ID string `json:"id"`
			} `json:"agents"`
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		t.Fatalf("decode completed result %s: %v", result, err)
	}
	if len(response.StructuredContent.Agents) != 1 || response.StructuredContent.Agents[0].ID != "http-op-agent" {
		t.Fatalf("unexpected completed list_agents result: %s", result)
	}
}

func TestBridgeOperationReadFileDispatchUsesArguments(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()
	ctx := context.Background()
	if err := srv.store.initBridgeOperations(ctx); err != nil {
		t.Fatal(err)
	}
	if err := createTestAgent(srv.store, ctx, Agent{ID: "read-agent", Name: "Agent", Enabled: true, AgentTokenHash: hashSecret("agent"), AllowedTools: "read_file"}, "read-agent", ""); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.CreateAccessToken(ctx, AccessToken{TokenHash: hashSecret("read-token"), ClientID: "read-agent", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	_, err := srv.store.db.ExecContext(ctx, `INSERT INTO bridge_operations(id,client_id,key,name,agent_id,args_hash,status,created_at,expires_at) VALUES('read-op','read-agent','1-550e8400-e29b-41d4-a716-446655440000','read_file','read-agent','hash','dispatching',?,?)`, time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	rt := newAgentRuntime("read-agent")
	srv.runtimes["read-agent"] = rt
	_, stream, _ := rt.activateAgentStream(ctx)
	done := make(chan struct{})
	go func() {
		srv.runBridgeOperation("read-token", "read-op", bridgeOperationRequest{Name: "read_file", AgentID: "read-agent"}, json.RawMessage(`{"path":"docs/guide.txt"}`))
		close(done)
	}()
	select {
	case call := <-rt.queue:
		var msg struct {
			ID     string `json:"id"`
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		if err := json.Unmarshal(call.Request, &msg); err != nil {
			t.Fatal(err)
		}
		if msg.Params.Name != "read_file" || msg.Params.Arguments["path"] != "docs/guide.txt" || msg.Params.Arguments["agent_id"] != nil {
			t.Fatalf("unexpected dispatched call: %s", call.Request)
		}
		resp, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{"content": []any{map[string]any{"type": "text", "text": "ok"}}}})
		rt.mu.Lock()
		pending := rt.pending[call.ID]
		rt.mu.Unlock()
		if pending == nil {
			t.Fatal("missing pending result channel")
		}
		pending <- protocol.AgentResponse{ID: call.ID, Response: resp}
	case <-time.After(time.Second):
		t.Fatal("read_file call was not dispatched")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("operation did not finish")
	}
	rt.deactivateAgentStream(stream)
	var status string
	var result []byte
	if err := srv.store.db.QueryRowContext(ctx, `SELECT status,result FROM bridge_operations WHERE id='read-op'`).Scan(&status, &result); err != nil {
		t.Fatal(err)
	}
	if status != "completed" {
		t.Fatalf("status=%s result=%s", status, result)
	}
}
