const state = {
  csrfToken: '',
  authMode: 'login',
  user: null,
  conversations: [],
  activeConversationId: null,
  streamInProgress: false,
  messages: [],
  aiConfigured: false,
  theme: 'midnight'
};

const els = {
  messages: document.getElementById('messages'),
  promptInput: document.getElementById('promptInput'),
  sendBtn: document.getElementById('sendBtn'),
  statusDot: document.getElementById('statusDot'),
  connectionStatus: document.getElementById('connectionStatus'),
  authModal: document.getElementById('authModal'),
  settingsModal: document.getElementById('settingsModal'),
  authForm: document.getElementById('authForm'),
  authMessage: document.getElementById('authMessage'),
  authEmail: document.getElementById('authEmail'),
  authPassword: document.getElementById('authPassword'),
  personalityInput: document.getElementById('personalityInput'),
  voiceEnabledInput: document.getElementById('voiceEnabledInput'),
  themeSelect: document.getElementById('themeSelect'),
  connectionInfo: document.getElementById('connectionInfo'),
  moodLabel: document.getElementById('moodLabel'),
  avatarStage: document.getElementById('avatarStage')
};

function setStatus(connected, label) {
  els.statusDot.classList.toggle('connected', connected);
  els.connectionStatus.textContent = label;
  els.moodLabel.textContent = connected ? 'ONLINE' : 'AGUARDANDO';
}

function renderWelcome() {
  els.messages.innerHTML = `
    <div class="welcome-card">
      <div class="welcome-mark">C</div>
      <h1>Ei. Eu sou a <span>Capri.</span></h1>
      <p>Uma plataforma de IA com identidade cyberpunk, histórico persistente e backend seguro para conversar, organizar ideias e manter contexto.</p>
    </div>
  `;
}

function createMessageBubble(role, text) {
  const row = document.createElement('div');
  row.className = `message-row ${role === 'user' ? 'user' : ''}`;

  const avatar = document.createElement('div');
  avatar.className = 'message-avatar';
  avatar.textContent = role === 'user' ? 'U' : 'C';

  const bubble = document.createElement('div');
  bubble.className = 'message-bubble';
  bubble.textContent = text;

  row.appendChild(role === 'user' ? bubble : avatar);
  row.appendChild(role === 'user' ? avatar : bubble);

  return row;
}

function appendMessage(role, text) {
  const row = createMessageBubble(role, text);
  els.messages.appendChild(row);
  els.messages.scrollTop = els.messages.scrollHeight;
}

function setAuthVisible(visible) {
  els.authModal.classList.toggle('hidden', !visible);
}

function toggleSidebar() {
  document.querySelector('.sidebar').classList.toggle('open');
}

async function apiFetch(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
      ...(state.csrfToken ? { 'x-csrf-token': state.csrfToken } : {})
    },
    credentials: 'same-origin'
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || 'Erro na requisição.');
  }

  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return response.json();
  }

  return response;
}

async function loadSession() {
  try {
    const data = await apiFetch('/api/session', { method: 'GET' });
    state.csrfToken = data.csrfToken || '';
    state.user = data.user || null;
    state.aiConfigured = data.aiConfigured;
    if (data.user) {
      setStatus(true, 'Sistema autenticado');
      await loadPreferences();
      await loadConversations();
      await loadAll();
    } else {
      setStatus(false, 'Faça login para continuar');
      setAuthVisible(true);
      renderWelcome();
    }
  } catch (error) {
    setStatus(false, error.message || 'Servidor indisponível');
  }
}

async function loadPreferences() {
  const data = await apiFetch('/api/preferences');
  state.theme = data.theme || 'midnight';
  els.personalityInput.value = data.personality || 'Clara, objetiva e útil.';
  els.voiceEnabledInput.checked = Boolean(data.voiceEnabled);
  els.themeSelect.value = state.theme;
  applyTheme(state.theme);
}

function applyTheme(theme) {
  const themes = {
    midnight: { bg: '#05080d', primary: '#39bfff', cyan: '#7de9ff' },
    graphite: { bg: '#0b0d12', primary: '#8ea3b4', cyan: '#dfeaf4' },
    neon: { bg: '#090b13', primary: '#7cff9d', cyan: '#dcffe6' }
  };

  const selected = themes[theme] || themes.midnight;
  document.documentElement.style.setProperty('--bg', selected.bg);
  document.documentElement.style.setProperty('--blue', selected.primary);
  document.documentElement.style.setProperty('--cyan', selected.cyan);
}

async function loadConversations() {
  const rows = await apiFetch('/api/conversations');
  state.conversations = rows || [];
  if (!state.conversations.length) {
    state.activeConversationId = null;
    renderWelcome();
    return;
  }

  if (!state.activeConversationId) state.activeConversationId = state.conversations[0].id;
  const active = state.conversations.find((item) => item.id === state.activeConversationId) || state.conversations[0];
  state.activeConversationId = active.id;
  await openConversation(active.id);
}

async function openConversation(id) {
  state.activeConversationId = id;
  const conversation = await apiFetch(`/api/conversations/${id}`);
  state.messages = conversation.messages || [];
  renderConversation();
}

function renderConversation() {
  if (!state.messages.length) {
    renderWelcome();
    return;
  }

  els.messages.innerHTML = '';
  state.messages.forEach((message) => {
    const row = createMessageBubble(message.role, message.content);
    els.messages.appendChild(row);
  });
  els.messages.scrollTop = els.messages.scrollHeight;
}

async function createConversation() {
  const name = prompt('Nome da conversa', 'Nova conversa');
  if (!name) return;
  const result = await apiFetch('/api/conversations', {
    method: 'POST',
    body: JSON.stringify({ title: name })
  });
  state.activeConversationId = result.id;
  await loadConversations();
}

async function sendMessage() {
  const text = els.promptInput.value.trim();
  if (!text || state.streamInProgress) return;
  if (!state.activeConversationId) {
    const created = await apiFetch('/api/conversations', {
      method: 'POST',
      body: JSON.stringify({ title: 'Nova conversa' })
    });
    state.activeConversationId = created.id;
  }

  appendMessage('user', text);
  els.promptInput.value = '';
  state.streamInProgress = true;
  setStatus(true, 'Capri processando...');

  try {
    const response = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': state.csrfToken },
      credentials: 'same-origin',
      body: JSON.stringify({ conversationId: state.activeConversationId, message: text })
    });

    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error || 'Erro ao enviar mensagem.');
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let assistantText = '';

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split('\n\n');
      buffer = parts.pop() || '';

      for (const block of parts) {
        const lines = block.split('\n');
        const event = lines[0]?.startsWith('event:') ? lines[0].replace('event: ', '') : '';
        const rawData = lines.find((line) => line.startsWith('data:')) || '';
        if (!rawData) continue;
        const payload = JSON.parse(rawData.replace('data: ', ''));

        if (event === 'delta' && payload.text) {
          assistantText += payload.text;
          const lastBubble = els.messages.lastElementChild;
          if (lastBubble && lastBubble.classList.contains('assistant-pending')) {
            lastBubble.querySelector('.message-bubble').textContent = assistantText;
          } else {
            const pending = createMessageBubble('assistant', assistantText);
            pending.classList.add('assistant-pending');
            const bubble = pending.querySelector('.message-bubble');
            bubble.textContent = assistantText;
            els.messages.appendChild(pending);
          }
        }
      }
    }

    if (!assistantText) {
      appendMessage('assistant', 'Não houve resposta útil do provedor de IA.');
    }
    setStatus(true, 'Sistema pronto');
  } catch (error) {
    appendMessage('assistant', `Erro: ${error.message}`);
    setStatus(false, 'Erro de conexão');
  } finally {
    state.streamInProgress = false;
    await loadConversations();
  }
}

async function savePreferences() {
  const payload = {
    personality: els.personalityInput.value,
    voiceEnabled: els.voiceEnabledInput.checked,
    theme: els.themeSelect.value
  };
  await apiFetch('/api/preferences', {
    method: 'PUT',
    body: JSON.stringify(payload)
  });
  state.theme = payload.theme;
  applyTheme(payload.theme);
  els.settingsModal.classList.add('hidden');
}

async function handleAuthSubmit(event) {
  event.preventDefault();
  const email = els.authEmail.value.trim();
  const password = els.authPassword.value;
  const endpoint = state.authMode === 'login' ? '/api/auth/login' : '/api/auth/register';

  try {
    const result = await apiFetch(endpoint, {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });

    state.csrfToken = result.csrfToken || state.csrfToken;
    state.user = result.user;
    setAuthVisible(false);
    setStatus(true, 'Autenticado');
    await loadPreferences();
    await loadConversations();
  } catch (error) {
    els.authMessage.textContent = error.message;
  }
}

async function loadAll() {
  try {
    const data = await apiFetch('/api/preferences');
    if (data.theme) applyTheme(data.theme);
    els.connectionInfo.textContent = state.aiConfigured ? 'Groq configurado no backend.' : 'Aguardando a chave GROQ no servidor.';
  } catch {
    els.connectionInfo.textContent = 'Configuração do backend ainda não disponível.';
  }
}

function bindEvents() {
  document.getElementById('newConversationBtn').addEventListener('click', createConversation);
  document.getElementById('settingsBtn').addEventListener('click', () => els.settingsModal.classList.remove('hidden'));
  document.getElementById('themeBtn').addEventListener('click', () => {
    const themes = ['midnight', 'graphite', 'neon'];
    const next = themes[(themes.indexOf(state.theme) + 1) % themes.length];
    state.theme = next;
    els.themeSelect.value = next;
    applyTheme(next);
  });
  document.getElementById('mobileMenuBtn').addEventListener('click', toggleSidebar);
  document.getElementById('sendBtn').addEventListener('click', sendMessage);
  document.getElementById('promptInput').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      sendMessage();
    }
  });
  document.querySelectorAll('[data-close]').forEach((button) => {
    button.addEventListener('click', () => {
      const id = button.dataset.close;
      document.getElementById(id).classList.add('hidden');
    });
  });
  document.querySelectorAll('.tab-button').forEach((button) => {
    button.addEventListener('click', () => {
      state.authMode = button.dataset.mode;
      document.querySelectorAll('.tab-button').forEach((tab) => tab.classList.toggle('active', tab === button));
    });
  });
  els.authForm.addEventListener('submit', handleAuthSubmit);
  document.getElementById('saveSettingsBtn').addEventListener('click', savePreferences);
  document.getElementById('memoryBtn').addEventListener('click', () => {
    const memo = prompt('Adicionar memória persistente do usuário', '');
    if (!memo) return;
    apiFetch('/api/memories', { method: 'POST', body: JSON.stringify({ content: memo, kind: 'long' }) }).catch(() => {});
  });
  document.getElementById('moodBtn').addEventListener('click', () => {
    const value = prompt('Defina a personalidade da Capri', els.personalityInput.value || 'Clara, objetiva e útil.');
    if (value) {
      els.personalityInput.value = value;
      savePreferences();
    }
  });
  document.getElementById('clearBtn').addEventListener('click', () => {
    els.messages.innerHTML = '';
    renderWelcome();
  });
  document.getElementById('exportBtn').addEventListener('click', () => {
    const text = state.messages.map((item) => `${item.role}: ${item.content}`).join('\n\n');
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'capri-export.txt';
    anchor.click();
    URL.revokeObjectURL(url);
  });
  document.getElementById('adminBtn').addEventListener('click', async () => {
    try {
      await apiFetch('/api/admin/overview');
      alert('Área administrativa disponível após autenticação de administrador.');
    } catch {
      alert('Este recurso exige autenticação administrativa.');
    }
  });
}

bindEvents();
renderWelcome();
loadSession();
