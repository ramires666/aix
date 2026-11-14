package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

var bridgeOperationKey = regexp.MustCompile(`^[0-9]{1,16}-[0-9a-fA-F-]{36}$`)

type bridgeOperation struct {
	ID        string          `json:"id"`
	Key       string          `json:"key"`
	Status    string          `json:"status"`
	Name      string          `json:"name"`
	AgentID   string          `json:"agent_id"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
	ClientID  string          `json:"-"`
	Arguments json.RawMessage `json:"-"`
	ArgsHash  string          `json:"-"`
	Durable   bool            `json:"-"`
	CreatedAt time.Time       `json:"-"`
}

func (s *store) initBridgeOperations(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS bridge_operations (
		id TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES mcp_clients(id) ON DELETE CASCADE,
		key TEXT NOT NULL, name TEXT NOT NULL, agent_id TEXT NOT NULL, args_hash TEXT NOT NULL,
		status TEXT NOT NULL, result BLOB, error TEXT, created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL,
		args_json BLOB, durable INTEGER NOT NULL DEFAULT 0,
		UNIQUE(client_id,key))`); err != nil {
		return fmt.Errorf("initialize bridge operations: %w", err)
	}
	columns := map[string]bool{}
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(bridge_operations)`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, kind string
		var def sql.NullString
		if err = rows.Scan(&cid, &name, &kind, &notnull, &def, &pk); err != nil {
			break
		}
		columns[name] = true
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	if !columns["args_json"] {
		if _, err = s.db.ExecContext(ctx, `ALTER TABLE bridge_operations ADD COLUMN args_json BLOB`); err != nil {
			return err
		}
	}
	if !columns["durable"] {
		if _, err = s.db.ExecContext(ctx, `ALTER TABLE bridge_operations ADD COLUMN durable INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	if _, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_bridge_operations_expiry ON bridge_operations(expires_at)`); err != nil {
		return err
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `UPDATE bridge_operations SET result=NULL,error=NULL WHERE expires_at<=?`, now.Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM bridge_operations WHERE created_at<=?`, now.Add(-48*time.Hour).Format(time.RFC3339Nano)); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE bridge_operations SET status='outcome_unknown', result=NULL, error='server restarted during execution' WHERE durable=0 AND status IN ('accepted','dispatching')`)
	return err
}

type bridgeOperationRequest struct {
	Key       string         `json:"key"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
	AgentID   string         `json:"agent_id"`
}

func (s *server) handleBridgeCreateOperation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	client, err := s.authenticateMCP(r)
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	if !bridgeOperationOriginAllowed(client, r) {
		http.Error(w, "origin denied", 403)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid request body", 400)
		return
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var req bridgeOperationRequest
	if err = dec.Decode(&req); err != nil || dec.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid request", 400)
		return
	}
	if len(req.Key) > 128 || !bridgeOperationKey.MatchString(req.Key) || req.Name == "" || req.AgentID == "" || req.Arguments == nil {
		http.Error(w, "key, name, object arguments, and agent_id are required", 400)
		return
	}
	keyParts := strings.SplitN(req.Key, "-", 2)
	keyTime, e := strconv.ParseInt(keyParts[0], 10, 64)
	if e != nil || uuid.Validate(keyParts[1]) != nil {
		http.Error(w, "invalid key", 400)
		return
	}
	now := time.Now()
	kt := time.UnixMilli(keyTime)
	if strings.HasPrefix(req.Name, "browser_") {
		http.Error(w, "browser tools are not supported", 400)
		return
	}
	if _, exists := req.Arguments["agent_id"]; exists {
		http.Error(w, "agent_id is reserved", 400)
		return
	}
	if kt.After(now.Add(time.Minute)) {
		http.Error(w, "invalid key timestamp", 400)
		return
	}
	if !bridgeAllows(client, req.Name) {
		http.Error(w, "tool not allowed", 403)
		return
	}
	agents, err := s.mcpAgents(r.Context(), client)
	if err != nil {
		http.Error(w, "failed to load agents", 500)
		return
	}
	var agent *Agent
	for i := range agents {
		if agents[i].ID == req.AgentID && agents[i].Enabled {
			agent = &agents[i]
			break
		}
	}
	if agent == nil || !newToolPolicy(agent.AllowedTools, agent.DeniedTools).allows(req.Name) {
		http.Error(w, "agent or tool not available", 403)
		return
	}
	canonicalRequest, err := json.Marshal(map[string]any{"name": req.Name, "agent_id": req.AgentID, "arguments": req.Arguments})
	if err != nil {
		http.Error(w, "invalid arguments", 400)
		return
	}
	h := sha256.Sum256(canonicalRequest)
	argsHash := hex.EncodeToString(h[:])
	op, err := s.store.acceptBridgeOperation(r.Context(), client.ID, req, argsHash, now, req.Name != "list_agents" && s.runtimeFor(req.AgentID).durableOperations())
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "operation key expired", 410)
		return
	}
	if errors.Is(err, errBridgeOperationStaleKey) {
		http.Error(w, "stale key", 400)
		return
	}
	if errors.Is(err, errBridgeOperationConflict) {
		http.Error(w, "operation key reused with different arguments", 409)
		return
	}
	if errors.Is(err, errBridgeOperationLimit) {
		http.Error(w, "operation limit reached", 429)
		return
	}
	if err != nil {
		http.Error(w, "failed to accept operation", 500)
		return
	}
	started := false
	if op.Status == "accepted" {
		claimed, claimErr := s.store.claimBridgeOperation(r.Context(), op.ID)
		if claimErr != nil {
			http.Error(w, "failed to dispatch operation", http.StatusInternalServerError)
			return
		}
		if claimed {
			op.Status = "dispatching"
			started = true
			arguments := op.Arguments
			if !op.Durable {
				arguments, _ = json.Marshal(req.Arguments)
			}
			go s.runBridgeOperation(bearerToken(r), op.ID, req, arguments)
		} else {
			var message sql.NullString
			var result []byte
			if err := s.store.db.QueryRowContext(r.Context(), `SELECT status,result,error FROM bridge_operations WHERE id=?`, op.ID).Scan(&op.Status, &result, &message); err != nil {
				http.Error(w, "failed to load operation", 500)
				return
			}
			op.Result = result
			if message.Valid {
				op.Error = message.String
			}
		}
	}
	if !started && op.Status == "dispatching" && op.Durable && s.runtimeFor(op.AgentID).durableOperations() {
		go s.runBridgeOperation(bearerToken(r), op.ID, req, op.Arguments, true)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(op)
}

func (s *store) claimBridgeOperation(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE bridge_operations SET status='dispatching' WHERE id=? AND status='accepted'`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

var errBridgeOperationConflict = errors.New("bridge operation key conflict")
var errBridgeOperationLimit = errors.New("bridge operation limit reached")
var errBridgeOperationStaleKey = errors.New("stale bridge operation key")

func (s *store) acceptBridgeOperation(ctx context.Context, clientID string, req bridgeOperationRequest, argsHash string, now time.Time, durable ...bool) (bridgeOperation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return bridgeOperation{}, err
	}
	defer tx.Rollback()
	var op bridgeOperation
	var result []byte
	var e sql.NullString
	var expiry, existingHash, created string
	var durableInt int
	var storedArgs []byte
	err = tx.QueryRowContext(ctx, `SELECT id,key,name,agent_id,args_hash,status,result,error,expires_at,args_json,durable,created_at FROM bridge_operations WHERE client_id=? AND key=?`, clientID, req.Key).Scan(&op.ID, &op.Key, &op.Name, &op.AgentID, &existingHash, &op.Status, &result, &e, &expiry, &storedArgs, &durableInt, &created)
	if err == nil {
		op.Arguments = storedArgs
		op.ArgsHash = existingHash
		op.Durable = durableInt == 1
		op.CreatedAt = parseDBTime(created)
		op.ClientID = clientID
		if argsHash != existingHash {
			return bridgeOperation{}, errBridgeOperationConflict
		}
		if !parseDBTime(expiry).After(now) {
			return bridgeOperation{}, sql.ErrNoRows
		}
		op.Result = result
		if e.Valid {
			op.Error = e.String
		}
		return op, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return bridgeOperation{}, err
	}
	parts := strings.SplitN(req.Key, "-", 2)
	keyMillis, _ := strconv.ParseInt(parts[0], 10, 64)
	if time.UnixMilli(keyMillis).Before(now.Add(-5 * time.Minute)) {
		return bridgeOperation{}, errBridgeOperationStaleKey
	}
	if _, err = tx.ExecContext(ctx, `UPDATE bridge_operations SET result=NULL,error=NULL WHERE expires_at<=?`, now.UTC().Format(time.RFC3339Nano)); err != nil {
		return bridgeOperation{}, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM bridge_operations WHERE created_at<=?`, now.UTC().Add(-48*time.Hour).Format(time.RFC3339Nano)); err != nil {
		return bridgeOperation{}, err
	}
	var count, active int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(CASE WHEN status IN ('accepted','dispatching') THEN 1 ELSE 0 END),0) FROM bridge_operations WHERE client_id=? AND created_at>?`, clientID, now.UTC().Add(-24*time.Hour).Format(time.RFC3339Nano)).Scan(&count, &active); err != nil {
		return bridgeOperation{}, err
	}
	if count >= 1000 || active >= 32 {
		return bridgeOperation{}, errBridgeOperationLimit
	}
	op = bridgeOperation{ID: uuid.NewString(), Key: req.Key, Name: req.Name, AgentID: req.AgentID, ClientID: clientID, ArgsHash: argsHash, Status: "accepted", CreatedAt: now, Durable: len(durable) > 0 && durable[0]}
	if op.Durable {
		op.Arguments, err = json.Marshal(req.Arguments)
		if err != nil {
			return bridgeOperation{}, err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO bridge_operations(id,client_id,key,name,agent_id,args_hash,status,created_at,expires_at,args_json,durable) VALUES(?,?,?,?,?,?, 'accepted',?,?,?,?)`, op.ID, clientID, req.Key, req.Name, req.AgentID, argsHash, now.UTC().Format(time.RFC3339Nano), now.Add(24*time.Hour).UTC().Format(time.RFC3339Nano), nullBytes(op.Arguments), op.Durable)
	if err != nil {
		return bridgeOperation{}, err
	}
	return op, tx.Commit()
}

func (s *server) runBridgeOperation(token, id string, req bridgeOperationRequest, args json.RawMessage, recovery ...bool) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	client, err := s.authenticateMCP(r)
	if err != nil {
		s.finishBridgeOperation(ctx, id, "failed", nil, err.Error())
		return
	}
	if !bridgeAllows(client, req.Name) {
		s.finishBridgeOperation(ctx, id, "failed", nil, "tool not allowed")
		return
	}
	agents, err := s.mcpAgents(ctx, client)
	if err != nil {
		s.finishBridgeOperation(ctx, id, "failed", nil, "failed to load agent")
		return
	}
	var found *Agent
	for i := range agents {
		if agents[i].ID == req.AgentID && agents[i].Enabled {
			found = &agents[i]
			break
		}
	}
	if found == nil || !newToolPolicy(found.AllowedTools, found.DeniedTools).allows(req.Name) {
		s.finishBridgeOperation(ctx, id, "failed", nil, "agent or tool no longer available")
		return
	}
	var durable bool
	var key, storedClient string
	var storedArgs []byte
	var argsHash string
	if err := s.store.db.QueryRowContext(ctx, `SELECT key,client_id,durable,args_json,args_hash FROM bridge_operations WHERE id=?`, id).Scan(&key, &storedClient, &durable, &storedArgs, &argsHash); err != nil {
		s.finishBridgeOperation(ctx, id, "outcome_unknown", nil, "operation intent unavailable")
		return
	}
	if durable {
		if storedClient != client.ID {
			s.finishBridgeOperation(ctx, id, "outcome_unknown", nil, "operation client changed")
			return
		}
		if s.runtimeFor(req.AgentID).isOnline() && !s.runtimeFor(req.AgentID).durableOperations() {
			s.finishBridgeOperation(ctx, id, "outcome_unknown", nil, "connected agent does not support operation journal")
			return
		}
		if !s.runtimeFor(req.AgentID).durableOperations() {
			return
		}
		op := bridgeOperation{ID: id, Key: key, Name: req.Name, AgentID: req.AgentID, ClientID: client.ID, Arguments: storedArgs, ArgsHash: argsHash, Durable: true}
		if len(recovery) > 0 && recovery[0] {
			if s.callDurableBridgeOperation(ctx, op, true) {
				s.callDurableBridgeOperation(ctx, op, false)
			}
		} else {
			s.callDurableBridgeOperation(ctx, op, false)
		}
		return
	}
	var argv map[string]any
	if json.Unmarshal(args, &argv) != nil {
		s.finishBridgeOperation(ctx, id, "failed", nil, "invalid stored arguments")
		return
	}
	if req.Name != "list_agents" {
		argv["agent_id"] = req.AgentID
	}
	call, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": req.Name, "arguments": argv}})
	response, err := s.executeMCPTool(ctx, client, call, "v5")
	if err != nil {
		s.finishBridgeOperation(ctx, id, "outcome_unknown", nil, "execution outcome unknown")
		return
	}
	var envelope struct {
		Error  json.RawMessage `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(response, &envelope) != nil {
		s.finishBridgeOperation(ctx, id, "outcome_unknown", nil, "execution outcome unknown")
		return
	}
	message := ""
	status := "completed"
	if len(envelope.Error) > 0 && string(envelope.Error) != "null" {
		status = "failed"
	}
	var toolResult struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(envelope.Result, &toolResult) == nil && toolResult.IsError {
		status = "failed"
		if len(toolResult.Content) > 0 {
			message = toolResult.Content[0].Text
		}
	}
	result := envelope.Result
	if status == "failed" {
		var rpcError struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(envelope.Error, &rpcError)
		message = rpcError.Message
		if message == "" {
			message = "tool execution failed"
		}
	}
	s.finishBridgeOperation(ctx, id, status, result, message)
}

func (s *server) callDurableBridgeOperation(ctx context.Context, op bridgeOperation, lookup bool) bool {
	if !s.runtimeFor(op.AgentID).durableOperations() {
		return false
	}
	params := map[string]any{"client_id": op.ClientID, "agent_id": op.AgentID, "key": op.Key}
	method := "bridge/operations/lookup"
	if !lookup {
		method = "bridge/operations/create"
		params["name"] = op.Name
		var args map[string]any
		if json.Unmarshal(op.Arguments, &args) != nil || args == nil {
			s.finishBridgeOperation(ctx, op.ID, "outcome_unknown", nil, "stored arguments unavailable")
			return false
		}
		if op.ArgsHash != "" {
			canonical, _ := json.Marshal(map[string]any{"name": op.Name, "agent_id": op.AgentID, "arguments": args})
			digest := sha256.Sum256(canonical)
			if hex.EncodeToString(digest[:]) != op.ArgsHash {
				s.finishBridgeOperation(ctx, op.ID, "outcome_unknown", nil, "stored arguments changed")
				return false
			}
		}
		params["arguments"] = args
	}
	call, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": op.ID, "method": method, "params": params})
	response, err := s.runtimeFor(op.AgentID).callAgent(ctx, call, s.timeout)
	if err != nil {
		return false
	} // The agent may have accepted the request; recovery must inspect its journal.
	var envelope struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			Status      string          `json:"status"`
			OperationID string          `json:"operation_id"`
			Result      json.RawMessage `json:"result"`
		} `json:"result"`
	}
	if json.Unmarshal(response.Response, &envelope) != nil || len(envelope.Error) > 0 && string(envelope.Error) != "null" {
		s.finishBridgeOperation(ctx, op.ID, "outcome_unknown", nil, "agent journal response invalid")
		return false
	}
	if envelope.Result.Status != "not_found" && envelope.Result.Status != "expired" {
		digest := sha256.Sum256([]byte(op.Key))
		if envelope.Result.OperationID != "op_"+hex.EncodeToString(digest[:]) {
			s.finishBridgeOperation(ctx, op.ID, "outcome_unknown", nil, "agent journal operation identity changed")
			return false
		}
	}
	switch envelope.Result.Status {
	case "completed":
		var toolResult map[string]any
		if json.Unmarshal(envelope.Result.Result, &toolResult) != nil || toolResult == nil {
			s.finishBridgeOperation(ctx, op.ID, "outcome_unknown", nil, "agent journal result missing")
			return false
		}
		s.finishBridgeOperation(ctx, op.ID, "completed", envelope.Result.Result, "")
	case "failed":
		var tool struct {
			IsError bool `json:"isError"`
		}
		_ = json.Unmarshal(envelope.Result.Result, &tool)
		if tool.IsError {
			s.finishBridgeOperation(ctx, op.ID, "failed", envelope.Result.Result, "")
			return false
		}
		var failure struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(envelope.Result.Result, &failure)
		if failure.Message == "" {
			failure.Message = "agent operation failed"
		}
		s.finishBridgeOperation(ctx, op.ID, "failed", nil, failure.Message)
	case "not_found":
		if lookup {
			stamp, _, _ := strings.Cut(op.Key, "-")
			millis, _ := strconv.ParseInt(stamp, 10, 64)
			if len(op.Arguments) == 0 || time.Since(time.UnixMilli(millis)) >= 24*time.Hour {
				s.finishBridgeOperation(ctx, op.ID, "outcome_unknown", nil, "operation intent expired")
				return false
			}
			return true
		}
	case "running":
		return false
	case "expired", "outcome_unknown":
		s.finishBridgeOperation(ctx, op.ID, "outcome_unknown", nil, "agent execution outcome unknown")
	default:
		s.finishBridgeOperation(ctx, op.ID, "outcome_unknown", nil, "agent journal response invalid")
	}
	return false
}

func (s *server) finishBridgeOperation(ctx context.Context, id, status string, result json.RawMessage, message string) {
	writeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := s.store.db.ExecContext(writeCtx, `UPDATE bridge_operations SET status=?,result=?,error=? WHERE id=? AND status IN ('accepted','dispatching')`, status, nullBytes(result), nullString(message), id)
	if err != nil {
		return
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return
	}
}
func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func bridgeOperationOriginAllowed(client *MCPClient, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if client.BridgeGrant == nil {
		return false
	}
	return origin == "chrome-extension://"+client.BridgeGrant.ExtensionID
}

func (s *server) handleBridgeGetOperation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	client, err := s.authenticateMCP(r)
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	if !bridgeOperationOriginAllowed(client, r) {
		http.Error(w, "origin denied", 403)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/bridge/v1/operations/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "not found", 404)
		return
	}
	var op bridgeOperation
	var result []byte
	var e sql.NullString
	var expiry string
	column, value := "id", id
	if id == "by-key" {
		column, value = "key", r.URL.Query().Get("key")
		parts := strings.SplitN(value, "-", 2)
		if !bridgeOperationKey.MatchString(value) || len(parts) != 2 || uuid.Validate(parts[1]) != nil {
			http.Error(w, "invalid key", http.StatusBadRequest)
			return
		}
	}
	var durableInt int
	var storedArgs []byte
	err = s.store.db.QueryRowContext(r.Context(), `SELECT id,key,name,agent_id,status,result,error,expires_at,args_json,args_hash,durable FROM bridge_operations WHERE `+column+`=? AND client_id=?`, value, client.ID).Scan(&op.ID, &op.Key, &op.Name, &op.AgentID, &op.Status, &result, &e, &expiry, &storedArgs, &op.ArgsHash, &durableInt)
	if errors.Is(err, sql.ErrNoRows) {
		if column == "key" {
			keyMillis, parseErr := strconv.ParseInt(strings.SplitN(value, "-", 2)[0], 10, 64)
			if parseErr != nil || time.UnixMilli(keyMillis).After(time.Now().Add(time.Minute)) {
				http.Error(w, "invalid key timestamp", http.StatusBadRequest)
				return
			}
			status := "not_found"
			if time.UnixMilli(keyMillis).Before(time.Now().Add(-5 * time.Minute)) {
				status = "expired"
			}
			writeJSON(w, map[string]string{"status": status})
			return
		}
		http.Error(w, "not found", 404)
		return
	}
	if err != nil {
		http.Error(w, "failed to load operation", 500)
		return
	}
	op.Arguments = storedArgs
	if !parseDBTime(expiry).After(time.Now()) {
		writeJSON(w, map[string]string{"status": "expired"})
		return
	}
	agents, err := s.mcpAgents(r.Context(), client)
	if err != nil {
		http.Error(w, "failed to load agent", 500)
		return
	}
	var agent *Agent
	for i := range agents {
		if agents[i].ID == op.AgentID && agents[i].Enabled {
			agent = &agents[i]
			break
		}
	}
	if agent == nil || !bridgeAllows(client, op.Name) || !newToolPolicy(agent.AllowedTools, agent.DeniedTools).allows(op.Name) {
		http.Error(w, "operation access revoked", 403)
		return
	}
	if durableInt == 1 && (op.Status == "accepted" || op.Status == "dispatching") && s.runtimeFor(op.AgentID).isOnline() && !s.runtimeFor(op.AgentID).durableOperations() {
		s.finishBridgeOperation(r.Context(), op.ID, "outcome_unknown", nil, "connected agent does not support operation journal")
		_ = s.store.db.QueryRowContext(r.Context(), `SELECT status,result,error FROM bridge_operations WHERE id=?`, op.ID).Scan(&op.Status, &result, &e)
	}
	if durableInt == 1 && (op.Status == "accepted" || op.Status == "dispatching") && s.runtimeFor(op.AgentID).durableOperations() {
		op.ClientID = client.ID
		ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
		notFound := s.callDurableBridgeOperation(ctx, op, true)
		cancel()
		_ = s.store.db.QueryRowContext(r.Context(), `SELECT status,result,error FROM bridge_operations WHERE id=?`, op.ID).Scan(&op.Status, &result, &e)
		if notFound && (op.Status == "accepted" || op.Status == "dispatching") {
			op.Status = "not_found"
		}
	}
	op.Result = result
	if e.Valid {
		op.Error = e.String
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(op)
}
