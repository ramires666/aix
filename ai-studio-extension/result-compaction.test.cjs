const test = require('node:test');
const assert = require('node:assert/strict');
const { buildResult } = require('./protocol.js');

const wrap = result => JSON.parse(buildResult({ operationId: 'op-1', name: 'exec_command', result, turnless: true })).result;

test('omits only a JSON text mirror of structuredContent without changing the saved result', () => {
  const stdout = 'строка 😀\n'.repeat(8000);
  const structuredContent = { status: 'exited', stdout, stderr: '', stdout_next_offset: Buffer.byteLength(stdout), exit_code: 0 };
  const result = {
    isError: false,
    structuredContent,
    content: [
      { type: 'text', text: JSON.stringify({ stdout, exit_code: 0, status: 'exited', stderr: '', stdout_next_offset: Buffer.byteLength(stdout) }) },
      { type: 'text', text: 'Separate diagnostic note' },
      { type: 'resource', resource: { uri: 'urn:test:file', blob: 'YWJj' } },
    ],
    metadata: { source: 'agent' },
  };
  const original = structuredClone(result);
  const compact = wrap(result);
  assert.deepEqual(compact, { ...result, content: result.content.slice(1) });
  assert.deepEqual(result, original);
  assert.ok(Buffer.byteLength(JSON.stringify(result)) - Buffer.byteLength(JSON.stringify(compact)) > 80_000);
});

test('retains text when JSON is different, malformed, or structuredContent is absent', () => {
  const structuredContent = { status: 'exited', stdout: 'ok', exit_code: 0 };
  for (const text of [
    JSON.stringify({ status: 'exited', stdout: 'changed', exit_code: 0 }),
    JSON.stringify({ status: 'exited', stdout: 'ok' }),
    '{bad json',
    'ok',
  ]) {
    const result = { structuredContent, content: [{ type: 'text', text }] };
    assert.deepEqual(wrap(result), result);
  }
  const withoutStructured = { content: [{ type: 'text', text: '{"ok":true}' }] };
  assert.deepEqual(wrap(withoutStructured), withoutStructured);
});

test('retains errors and every non-text content item', () => {
  const structuredContent = { error: { code: 'failed', message: 'detail' } };
  const result = { isError: true, structuredContent, content: [
    { type: 'text', text: JSON.stringify(structuredContent) },
    { type: 'text', text: 'stderr: important detail' },
    { type: 'image', mimeType: 'image/png', data: 'YWJj' },
  ] };
  assert.deepEqual(wrap(result), { ...result, content: result.content.slice(1) });
  const transport = JSON.parse(buildResult({ operationId: 'op-2', name: 'exec_command', result, error: 'lost response' }));
  assert.equal(transport.transport_error, 'lost response');
  assert.equal('result' in transport, false);
});
