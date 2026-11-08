import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server.js';

async function setup(t, options = {}) {
  const app = createApp({ dbPath: ':memory:', production: false, publicDir: './public', ...options });
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, () => resolve(instance));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  let cookie = '';
  let csrf = '';
  const request = async (url, opts = {}) => {
    const headers = new Headers(opts.headers || {});
    if (cookie) headers.set('Cookie', cookie);
    if (opts.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    if (csrf && opts.method && !['GET', 'HEAD'].includes(opts.method)) headers.set('X-CSRF-Token', csrf);
    const response = await fetch(base + url, { ...opts, headers });
    const setCookie = response.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0];
    return response;
  };
  const sessionResponse = await request('/api/session');
  csrf = (await sessionResponse.json()).csrfToken;
  const register = async (email = 'test@example.com') => {
    const response = await request('/api/auth/register', { method: 'POST', body: JSON.stringify({ email, password: 'a-strong-password-123' }) });
    const payload = await response.json();
    if (payload.csrfToken) csrf = payload.csrfToken;
    return { response, payload };
  };
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    app.locals.db.close();
  }));
  return { request, register };
}

test('health reports whether Groq has been configured without exposing credentials', async (t) => {
  const { request } = await setup(t, { groqApiKey: 'secret-test-key' });
  const response = await request('/api/health');
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.aiConfigured, true);
  assert.equal(JSON.stringify(payload).includes('secret-test-key'), false);
});

test('register, authenticate, create conversations and enforce ownership', async (t) => {
  const { request, register } = await setup(t);
  const { response: registered } = await register();
  assert.equal(registered.status, 201);
  const created = await request('/api/conversations', { method: 'POST', body: JSON.stringify({ title: 'Teste' }) });
  assert.equal(created.status, 201);
  const conversation = await created.json();
  const loaded = await request(`/api/conversations/${conversation.id}`);
  assert.equal(loaded.status, 200);
  assert.equal((await loaded.json()).title, 'Teste');
});

test('unauthenticated requests cannot access private data', async (t) => {
  const { request } = await setup(t);
  assert.equal((await request('/api/conversations')).status, 401);
  assert.equal((await request('/api/memories')).status, 401);
});

test('mutating requests require a CSRF token', async (t) => {
  const { request, register } = await setup(t);
  await register();
  const response = await request('/api/conversations', { method: 'POST', headers: { 'X-CSRF-Token': 'invalid' }, body: JSON.stringify({ title: 'Sem CSRF' }) });
  assert.equal(response.status, 403);
});

test('Groq chat fails clearly when the server key is not configured', async (t) => {
  const { request, register } = await setup(t);
  await register();
  const conversation = await (await request('/api/conversations', { method: 'POST', body: JSON.stringify({ title: 'IA' }) })).json();
  const response = await request('/api/chat', { method: 'POST', body: JSON.stringify({ conversationId: conversation.id, message: 'Olá' }) });
  assert.equal(response.status, 503);
  assert.match((await response.json()).error, /GROQ_API_KEY/);
});

test('user data APIs persist tasks, notes and memories', async (t) => {
  const { request, register } = await setup(t);
  await register();
  const taskResponse = await request('/api/tasks', { method: 'POST', body: JSON.stringify({ title: 'Revisar plano' }) });
  assert.equal(taskResponse.status, 201);
  const task = await taskResponse.json();
  assert.equal((await request(`/api/tasks/${task.id}`, { method: 'PATCH', body: JSON.stringify({ done: true }) })).status, 200);
  assert.equal((await (await request('/api/tasks')).json())[0].done, 1);
  assert.equal((await request('/api/notes', { method: 'POST', body: JSON.stringify({ title: 'Ideia', body: 'Conteúdo' }) })).status, 201);
  assert.equal((await request('/api/memories', { method: 'POST', body: JSON.stringify({ kind: 'long', content: 'Prefere respostas em português.' }) })).status, 201);
});
