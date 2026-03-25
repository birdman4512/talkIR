'use strict';

// ─── State ────────────────────────────────────────────────────────────────────
const state = {
  conversationHistory: [],
  streaming: false,
  abortController: null,
};

// ─── DOM refs ─────────────────────────────────────────────────────────────────
const messagesEl      = document.getElementById('messages');
const chatForm        = document.getElementById('chatForm');
const queryInput      = document.getElementById('queryInput');
const sendBtn         = document.getElementById('sendBtn');
const indicesList     = document.getElementById('indicesList');
const selectAllCb     = document.getElementById('selectAll');
const maxResultsInput = document.getElementById('maxResults');
const maxResultsVal   = document.getElementById('maxResultsVal');
const allResultsCb    = document.getElementById('allResults');
const smartQueryCb    = document.getElementById('smartQuery');
const conciseModeCb   = document.getElementById('conciseMode');
const refreshBtn      = document.getElementById('refreshIndices');
const clearBtn        = document.getElementById('clearChat');
const modelBadge      = document.getElementById('modelBadge');
const providerSelect  = document.getElementById('providerSelect');
const modelSelect     = document.getElementById('modelSelect');
const catalogueList   = document.getElementById('catalogueList');
const refreshCatalogue = document.getElementById('refreshCatalogue');
const openSettingsBtn  = document.getElementById('openSettings');
const closeSettingsBtn = document.getElementById('closeSettings');
const settingsModal    = document.getElementById('settingsModal');
const stopBtn          = document.getElementById('stopBtn');

// ─── Sidebar resize ───────────────────────────────────────────────────────────
(function () {
  const handle = document.getElementById('resizeHandle');
  const shell  = document.querySelector('.shell');
  const sidebar = document.querySelector('.sidebar');
  let startX = 0, startW = 0;

  handle.addEventListener('mousedown', (e) => {
    startX = e.clientX;
    startW = sidebar.offsetWidth;
    handle.classList.add('active');
    document.body.style.cursor    = 'col-resize';
    document.body.style.userSelect = 'none';

    function onMove(e) {
      const w = Math.max(160, Math.min(480, startW + (e.clientX - startX)));
      shell.style.gridTemplateColumns = `${w}px 1fr`;
    }
    function onUp() {
      handle.classList.remove('active');
      document.body.style.cursor    = '';
      document.body.style.userSelect = '';
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup',   onUp);
    }
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup',   onUp);
  });
})();

// ─── Initialise ───────────────────────────────────────────────────────────────
loadIndices();
loadModelInfo();
loadModels();
providerSelect.addEventListener('change', onProviderChange);
refreshCatalogue.addEventListener('click', loadCatalogue);
openSettingsBtn.addEventListener('click', () => {
  settingsModal.classList.add('open');
  loadCatalogue();
});
closeSettingsBtn.addEventListener('click', () => settingsModal.classList.remove('open'));
settingsModal.addEventListener('click', (e) => {
  if (e.target === settingsModal) settingsModal.classList.remove('open');
});

maxResultsInput.addEventListener('input', () => {
  maxResultsVal.textContent = maxResultsInput.value;
});

allResultsCb.addEventListener('change', () => {
  maxResultsInput.disabled = allResultsCb.checked;
  maxResultsVal.textContent = allResultsCb.checked ? '∞' : maxResultsInput.value;
});

// Auto-resize textarea
queryInput.addEventListener('input', () => {
  queryInput.style.height = 'auto';
  queryInput.style.height = Math.min(queryInput.scrollHeight, 140) + 'px';
});

// Submit on Enter (Shift+Enter = newline)
queryInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    if (!state.streaming) chatForm.requestSubmit();
  }
});

refreshBtn.addEventListener('click', loadIndices);
clearBtn.addEventListener('click', clearChat);
selectAllCb.addEventListener('change', toggleSelectAll);
chatForm.addEventListener('submit', handleSubmit);

// ─── Indices ──────────────────────────────────────────────────────────────────
async function loadIndices() {
  indicesList.innerHTML = '<span class="muted">Loading…</span>';
  try {
    const resp = await fetch('/api/indices');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const indices = await resp.json();

    if (indices.length === 0) {
      indicesList.innerHTML = '<span class="muted">No indices yet — drop .json files into ./logs/</span>';
      return;
    }

    indicesList.innerHTML = indices.map(idx => `
      <label class="check-label">
        <input type="checkbox" class="index-cb" value="${esc(idx.name)}" checked />
        ${esc(idx.name)}
        <span class="index-meta">${idx.doc_count.toLocaleString()} docs</span>
      </label>
    `).join('');
  } catch (err) {
    indicesList.innerHTML = `<span class="muted">Error: ${esc(String(err))}</span>`;
  }
}

function getSelectedIndices() {
  return [...document.querySelectorAll('.index-cb:checked')].map(cb => cb.value);
}

function toggleSelectAll() {
  document.querySelectorAll('.index-cb').forEach(cb => {
    cb.checked = selectAllCb.checked;
  });
}

// ─── Model info ───────────────────────────────────────────────────────────────
async function loadModelInfo() {
  try {
    const resp = await fetch('/api/info');
    if (!resp.ok) return;
    const data = await resp.json();
    if (data.model) modelBadge.textContent = `model: ${data.model}`;
  } catch { /* ignore */ }
}

const CLOUD_MODELS = {
  claude: [
    'claude-opus-4-6',
    'claude-sonnet-4-6',
    'claude-haiku-4-5-20251001',
  ],
  openai: [
    'gpt-4o',
    'gpt-4o-mini',
    'gpt-4-turbo',
  ],
};

async function loadModels() {
  try {
    const resp = await fetch('/api/models');
    if (!resp.ok) return;
    const ollamaModels = await resp.json();

    const infoResp = await fetch('/api/info');
    const info = infoResp.ok ? await infoResp.json() : {};
    const defaultModel = info.model || '';

    // Store Ollama models for later switching
    providerSelect._ollamaModels = ollamaModels;
    providerSelect._ollamaDefault = defaultModel;

    populateModels('ollama');

    modelSelect.addEventListener('change', () => {
      updateBadge();
    });
  } catch { /* ignore */ }
}

function populateModels(provider) {
  if (provider === 'ollama') {
    const models = providerSelect._ollamaModels || [];
    const def    = providerSelect._ollamaDefault || '';
    modelSelect.innerHTML = models.length
      ? models.map(m => `<option value="${esc(m)}" ${m === def ? 'selected' : ''}>${esc(m)}</option>`).join('')
      : '<option value="">No local models found</option>';
  } else {
    const models = CLOUD_MODELS[provider] || [];
    modelSelect.innerHTML = models.map(m => `<option value="${esc(m)}">${esc(m)}</option>`).join('');
  }
  updateBadge();
}

function onProviderChange() {
  populateModels(providerSelect.value);
}

function updateBadge() {
  const provider = providerSelect.value;
  const model    = modelSelect.value;
  const label    = provider === 'ollama' ? model : `${provider}: ${model}`;
  modelBadge.textContent = `model: ${label}`;
}

function getSelectedModel()    { return modelSelect.value || ''; }
function getSelectedProvider() { return providerSelect.value || 'ollama'; }

// ─── Model catalogue ──────────────────────────────────────────────────────────
async function loadCatalogue() {
  catalogueList.innerHTML = '<span class="muted">Loading…</span>';
  try {
    const resp = await fetch('/api/models/catalogue');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const models = await resp.json();
    catalogueList.innerHTML = models.map(m => `
      <div class="catalogue-row" data-model="${esc(m.name)}">
        <div class="catalogue-info">
          <span class="catalogue-name">${esc(m.name)}</span>
          <span class="catalogue-desc muted">${esc(m.desc)}</span>
        </div>
        <div class="catalogue-right">
          <span class="catalogue-size muted">${esc(m.size)}</span>
          ${m.installed
            ? `<span class="catalogue-badge installed">✓</span>
               <button class="btn-delete" data-model="${esc(m.name)}" title="Delete model">🗑</button>`
            : `<button class="btn-pull" data-model="${esc(m.name)}">↓</button>`}
        </div>
      </div>
    `).join('');

    catalogueList.querySelectorAll('.btn-pull').forEach(btn => {
      btn.addEventListener('click', () => pullModel(btn.dataset.model, btn));
    });
    catalogueList.querySelectorAll('.btn-delete').forEach(btn => {
      btn.addEventListener('click', () => deleteModel(btn.dataset.model, btn));
    });
  } catch (err) {
    catalogueList.innerHTML = `<span class="muted">Error: ${esc(String(err))}</span>`;
  }
}

async function pullModel(modelName, btn) {
  const row = btn.closest('.catalogue-row');
  const progress = document.createElement('div');
  progress.className = 'pull-progress';
  btn.replaceWith(progress);

  try {
    const resp = await fetch('/api/models/pull', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: modelName }),
    });

    const reader  = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.startsWith('data:')) continue;
        const raw = line.slice(5).trim();
        if (!raw) continue;
        try {
          const chunk = JSON.parse(raw);
          if (chunk.error) { progress.textContent = `Error: ${chunk.error}`; return; }
          if (chunk.total && chunk.completed) {
            const pct = Math.round((chunk.completed / chunk.total) * 100);
            progress.textContent = `${pct}%`;
          } else if (chunk.status) {
            progress.textContent = chunk.status;
          }
        } catch { /* skip */ }
      }
    }

    // Refresh catalogue and model dropdown after successful pull
    await loadCatalogue();
    await loadModels();
  } catch (err) {
    progress.textContent = `Error: ${err}`;
  }
}

// ─── Status bar ───────────────────────────────────────────────────────────────
// Shows a persistent status bar above messages with elapsed time.
// Completely independent of the response bubble.
let _thinkingTimer = null;
let _thinkingStart = 0;
let _thinkingBase  = '';

let _statusBubble = null;

function startThinkingTimer(bubble, text) {
  _statusBubble  = bubble;
  _thinkingBase  = text;
  _thinkingStart = Date.now();
  _updateThinking();
  _thinkingTimer = setInterval(_updateThinking, 250);
}

function _updateThinking() {
  if (!_statusBubble) return;
  const secs = Math.floor((Date.now() - _thinkingStart) / 1000);
  _statusBubble.textContent = secs > 0 ? `${_thinkingBase} (${secs}s)` : _thinkingBase;
}

function stopThinkingTimer() {
  clearInterval(_thinkingTimer);
  _thinkingTimer = null;
  _statusBubble  = null;
}

async function deleteModel(modelName, btn) {
  if (!confirm(`Delete ${modelName}? You can re-download it later.`)) return;
  btn.disabled = true;
  btn.textContent = '…';
  try {
    const resp = await fetch(`/api/models/${encodeURIComponent(modelName)}`, { method: 'DELETE' });
    const data = await resp.json();
    if (data.error) { alert(`Error: ${data.error}`); btn.disabled = false; btn.textContent = '🗑'; return; }
    await loadCatalogue();
    await loadModels();
  } catch (err) {
    alert(`Error: ${err}`);
    btn.disabled = false;
    btn.textContent = '🗑';
  }
}

// ─── Chat ─────────────────────────────────────────────────────────────────────
async function handleSubmit(e) {
  e.preventDefault();
  const query = queryInput.value.trim();
  if (!query || state.streaming) return;

  const indices    = getSelectedIndices();
  const maxResults = allResultsCb.checked ? 10000 : parseInt(maxResultsInput.value, 10);
  const model      = getSelectedModel();
  const provider   = getSelectedProvider();

  const conciseSuffix = conciseModeCb.checked ? '\n\n[Be concise — answer in 3 to 5 sentences maximum.]' : '';

  appendMessage('user', query);
  state.conversationHistory.push({ role: 'user', content: query + conciseSuffix });
  queryInput.value = '';
  queryInput.style.height = 'auto';

  // Context message — separate chat element, appears before the response
  const contextMsg = document.createElement('div');
  contextMsg.className = 'msg context-msg';
  contextMsg.hidden = true;
  messagesEl.appendChild(contextMsg);

  // Generated query — collapsible panel, open by default
  const queryBlock = document.createElement('details');
  queryBlock.className = 'query-block';
  queryBlock.open = false;
  queryBlock.hidden = true;
  const querySummary = document.createElement('summary');
  querySummary.textContent = 'ES query';
  const queryCode = document.createElement('pre');
  queryCode.className = 'query-code';
  queryBlock.appendChild(querySummary);
  queryBlock.appendChild(queryCode);
  contextMsg.appendChild(queryBlock);

  // Records — collapsed by default
  const contextDetails = document.createElement('details');
  contextDetails.className = 'think-block context-block';
  const contextSummary = document.createElement('summary');
  contextDetails.appendChild(contextSummary);
  const contextBody = document.createElement('div');
  contextBody.className = 'think-body';
  contextDetails.appendChild(contextBody);
  contextMsg.appendChild(contextDetails);

  // Assistant message wrapper
  const msgEl = document.createElement('div');
  msgEl.className = 'msg assistant';
  messagesEl.appendChild(msgEl);

  // Status bubble (shown while waiting)
  const statusBubble = document.createElement('div');
  statusBubble.className = 'bubble status';
  msgEl.appendChild(statusBubble);

  // Thinking block (hidden until <think> tokens arrive)
  const thinkDetails = document.createElement('details');
  thinkDetails.className = 'think-block';
  thinkDetails.hidden = true;
  thinkDetails.innerHTML = '<summary>Reasoning</summary>';
  const thinkBody = document.createElement('div');
  thinkBody.className = 'think-body';
  thinkDetails.appendChild(thinkBody);
  msgEl.appendChild(thinkDetails);

  // Response bubble (shown when content arrives)
  const assistantBubble = document.createElement('div');
  assistantBubble.className = 'bubble cursor';
  assistantBubble.hidden = true;
  msgEl.appendChild(assistantBubble);

  // Live stats footer — shown during generation, replaced by final stats when done
  const liveStats = document.createElement('div');
  liveStats.className = 'msg-stats';
  liveStats.hidden = true;
  msgEl.appendChild(liveStats);

  let tokenCount  = 0;
  let genStart    = 0;
  let statsTimer  = null;

  function startGenStats() {
    genStart = Date.now();
    liveStats.hidden = false;
    statsTimer = setInterval(() => {
      const secs = ((Date.now() - genStart) / 1000).toFixed(1);
      const rate = genStart ? (tokenCount / ((Date.now() - genStart) / 1000)).toFixed(1) : 0;
      liveStats.textContent = `${tokenCount} tokens · ${rate} tok/s · ${secs}s`;
    }, 250);
  }

  function stopGenStats(finalStats) {
    clearInterval(statsTimer);
    statsTimer = null;
    if (finalStats && finalStats.tokens) {
      const s = finalStats;
      const parts = [`${s.tokens} tokens`];
      if (s.tokens_per_sec) parts.push(`${s.tokens_per_sec} tok/s`);
      if (s.duration_sec)   parts.push(`${s.duration_sec}s`);
      liveStats.textContent = parts.join(' · ');
    } else {
      liveStats.hidden = true;
    }
  }

  setStreaming(true);
  state.abortController = new AbortController();
  stopBtn.addEventListener('click', () => state.abortController.abort(), { once: true });
  startThinkingTimer(statusBubble, '[*] sending request…');
  scrollToBottom();

  let hasContent  = false;
  let fullReply   = '';

  try {
    const resp = await fetch('/api/chat', {
      method: 'POST',
      signal: state.abortController.signal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: query + conciseSuffix,
        indices,
        max_results: maxResults,
        conversation_history: state.conversationHistory.slice(-20),
        model,
        provider,
        smart_query: smartQueryCb.checked,
      }),
    });

    if (!resp.ok) {
      stopThinkingTimer();
      statusBubble.remove();
      appendMessage('error', `Server error ${resp.status}: ${await resp.text()}`);
      return;
    }

    const reader  = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer    = '';

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.startsWith('data:')) continue;
        const raw = line.slice(5).trim();
        if (!raw) continue;
        try {
          const chunk = JSON.parse(raw);

          if (chunk.error) {
            stopThinkingTimer();
            statusBubble.remove();
            appendMessage('error', chunk.error);
            return;
          }

          if (chunk.status) {
            _thinkingBase = formatStatus(chunk);
            _updateThinking();
          }

          if (chunk.generated_query) {
            queryCode.textContent = JSON.stringify(chunk.generated_query, null, 2);
            queryBlock.hidden = false;
            contextMsg.hidden = false;
            scrollToBottom();
          }

          if (chunk.query_warning) {
            const warn = document.createElement('div');
            warn.className = 'query-warning';
            warn.textContent = chunk.query_warning;
            contextMsg.appendChild(warn);
            contextMsg.hidden = false;
            scrollToBottom();
          }

          if (chunk.context !== undefined) {
            const n = chunk.context.length;
            contextMsg.hidden = false;
            if (n > 0) {
              contextSummary.textContent = `${n} record${n === 1 ? '' : 's'} sent to LLM`;
              contextBody.textContent = chunk.context
                .map((e, i) => `[${i + 1}] ${JSON.stringify(e, null, 2)}`)
                .join('\n\n');
            } else {
              contextSummary.textContent = 'No records found — LLM will respond without data context';
            }
            scrollToBottom();
          }

          if (chunk.thinking) {
            thinkDetails.hidden = false;
            thinkBody.textContent += chunk.thinking;
            scrollToBottom();
          }

          if (chunk.content !== undefined && (chunk.content || chunk.done)) {
            if (!hasContent) {
              hasContent = true;
              stopThinkingTimer();
              statusBubble.hidden = true;
              assistantBubble.hidden = false;
              startGenStats();
            }
            if (chunk.content) {
              tokenCount++;
              fullReply += chunk.content;
              assistantBubble.textContent = fullReply;
            }
            if (chunk.done) {
              assistantBubble.classList.remove('cursor');
              stopGenStats(chunk.stats);
            }
            scrollToBottom();
          }
        } catch { /* malformed chunk */ }
      }
    }

    assistantBubble.classList.remove('cursor');
    state.conversationHistory.push({ role: 'assistant', content: fullReply });

  } catch (err) {
    stopThinkingTimer();
    stopGenStats(null);
    assistantBubble.classList.remove('cursor');
    if (err.name !== 'AbortError') {
      appendMessage('error', String(err));
    } else if (!hasContent) {
      statusBubble.remove();
    }
  } finally {
    stopThinkingTimer();
    clearInterval(statsTimer);
    setStreaming(false);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function appendMessage(role, text, returnBubble = false) {
  const msg    = document.createElement('div');
  msg.className = `msg ${role}`;
  const bubble  = document.createElement('div');
  bubble.className = 'bubble';
  if (role === 'assistant') bubble.classList.add('cursor');
  bubble.textContent = text;
  msg.appendChild(bubble);
  messagesEl.appendChild(msg);
  scrollToBottom();
  return returnBubble ? bubble : msg;
}

function scrollToBottom() {
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function setStreaming(val) {
  state.streaming     = val;
  sendBtn.hidden      = val;
  sendBtn.disabled    = val;
  stopBtn.hidden      = !val;
  queryInput.disabled = val;
}

function clearChat() {
  state.conversationHistory = [];
  messagesEl.innerHTML = '';
  appendMessage('assistant', 'session cleared.');
}

function formatStatus(chunk) {
  if (chunk.status === 'searching') {
    const n = chunk.indices;
    return `[*] searching ${n === 0 ? 'all' : n} ${n === 1 ? 'index' : 'indices'}…`;
  }
  if (chunk.status === 'generating_query') {
    return '[*] generating es query…';
  }
  if (chunk.status === 'found') {
    return chunk.count > 0
      ? `[*] found ${chunk.count} event${chunk.count === 1 ? '' : 's'} — analysing…`
      : '[*] no matching events — analysing…';
  }
  return '[*] working…';
}

function esc(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
