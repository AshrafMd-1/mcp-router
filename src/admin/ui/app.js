const state = {
  page: 'clients',
  clients: [],
  connectors: []
};

const loginView = document.getElementById('loginView');
const app = document.getElementById('app');
const cards = document.getElementById('cards');
const pageTitle = document.getElementById('pageTitle');
const createBtn = document.getElementById('createBtn');
const modalWrap = document.getElementById('modalWrap');
const modal = document.getElementById('modal');
const errorBox = document.getElementById('errorBox');

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function setError(message, details) {
  if (!message) {
    errorBox.innerHTML = '';
    return;
  }

  const safeMessage = escapeHtml(message);
  const safeDetails = details ? escapeHtml(details) : '';
  errorBox.innerHTML = `
    <div class="notice">
      <strong>${safeMessage}</strong>
      ${safeDetails ? `<div style="margin-top:8px;"><div class="small">Technical details</div><div class="json-panel">${safeDetails}</div></div>` : ''}
    </div>
  `;
}

async function api(path, options = {}) {
  const hasBody = Object.prototype.hasOwnProperty.call(options, 'body');
  const res = await fetch(path, {
    ...options,
    headers: {
      ...(hasBody ? { 'Content-Type': 'application/json' } : {}),
      ...(options.headers || {})
    },
    credentials: 'same-origin'
  });

  const text = await res.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { message: text };
  }

  if (!res.ok) {
    const message = data.error || data.message || 'Request failed';
    const err = new Error(message);
    err.details = JSON.stringify(data, null, 2);
    throw err;
  }

  return data;
}

function openModal(html) {
  modal.innerHTML = html;
  modalWrap.classList.add('show');
}

function closeModal() {
  modalWrap.classList.remove('show');
  modal.innerHTML = '';
}

modalWrap.addEventListener('click', (e) => {
  if (e.target === modalWrap) {
    // intentionally no backdrop close
  }
});

function fmtDate(iso) {
  return new Date(iso).toLocaleString();
}

async function refreshClients() {
  const data = await api('/admin/clients');
  state.clients = data.clients || [];
}

async function refreshConnectors() {
  const data = await api('/admin/connectors');
  state.connectors = data.connectors || [];
}

async function loadToolCounts() {
  for (const c of state.connectors) {
    try {
      const catalog = await api(`/admin/tool-catalog?connectorId=${encodeURIComponent(c.id)}`);
      c.toolCount = (catalog.tools || []).length;
    } catch {
      c.toolCount = 0;
    }
  }
}

function render() {
  setError('');

  if (state.page === 'clients') {
    pageTitle.textContent = 'Clients';
    createBtn.textContent = 'Create Client';
    cards.innerHTML = state.clients
      .map(
        (c) => `
      <div class="card">
        <div class="card-title">${escapeHtml(c.name)}</div>
        <div class="small">Created: ${escapeHtml(fmtDate(c.createdAt))}</div>
        <div class="link-row">
          <button class="link-btn" data-act="edit-client" data-id="${escapeHtml(c.id)}">Edit</button>
          <button class="link-btn" data-act="delete-client" data-id="${escapeHtml(c.id)}">Delete</button>
        </div>
      </div>`
      )
      .join('');
    return;
  }

  pageTitle.textContent = 'Connectors';
  createBtn.textContent = 'Create Connector';
  cards.innerHTML = state.connectors
    .map((c) => {
      const healthy = c.healthStatus === 'healthy';
      const countTag = c.toolCount ?? 0;
      return `
      <div class="card">
        <div class="card-title">${escapeHtml(c.name)}</div>
        <div class="badge">Tools ${countTag}</div>
        <div class="badge ${healthy ? 'ok' : 'bad'}">${healthy ? 'alive' : 'dead'}</div>
        <div class="link-row">
          <button class="link-btn" data-act="edit-connector" data-id="${escapeHtml(c.id)}">Edit</button>
          <button class="link-btn" data-act="discover-connector" data-id="${escapeHtml(c.id)}">Refresh Tools</button>
          <button class="link-btn" data-act="delete-connector" data-id="${escapeHtml(c.id)}">Delete</button>
        </div>
      </div>`;
    })
    .join('');
}

async function loadDashboard() {
  await Promise.all([refreshClients(), refreshConnectors()]);
  await loadToolCounts();
  render();
}

async function fetchToolCatalogForConnector(connectorId) {
  try {
    const r = await api(`/admin/tool-catalog?connectorId=${encodeURIComponent(connectorId)}`);
    return r.tools || [];
  } catch {
    return [];
  }
}

function getClientById(id) {
  return state.clients.find((c) => c.id === id);
}

async function clientModal(clientId = null) {
  const existing = clientId ? getClientById(clientId) : null;
  let effectiveClientId = existing?.id ?? null;
  let formName = existing?.name || '';
  let formDescription = existing?.description || '';
  let activeTab = 'details';
  let selectedConnectorIds = new Set();
  let allowedTools = new Set();
  const toolCatalogByConnector = new Map();
  const sortedConnectors = [...state.connectors].sort((a, b) => a.name.localeCompare(b.name));
  let activeConnectorId = sortedConnectors[0]?.id ?? null;
  let tokens = [];
  let hasUnsavedChanges = false;
  let lastIssuedToken = null;

  const getConnectorById = (connectorId) => sortedConnectors.find((c) => c.id === connectorId) || null;

  const getConnectorByToolName = (toolName) => {
    for (const connector of sortedConnectors) {
      if (toolName.startsWith(`${connector.name}.`)) return connector;
    }
    return null;
  };

  const getToolShortName = (toolName, connector) => {
    if (connector && toolName.startsWith(`${connector.name}.`)) {
      return toolName.slice(connector.name.length + 1);
    }
    const parts = toolName.split('.');
    return parts.length > 1 ? parts.slice(1).join('.') : toolName;
  };

  const recomputeSelectedConnectorsFromAllowedTools = () => {
    const next = new Set();
    for (const toolName of allowedTools) {
      const connector = getConnectorByToolName(toolName);
      if (connector) next.add(connector.id);
    }
    selectedConnectorIds = next;
  };

  const countSelectedToolsForConnector = (connector) => {
    const prefix = `${connector.name}.`;
    let count = 0;
    for (const toolName of allowedTools) {
      if (toolName.startsWith(prefix)) count += 1;
    }
    return count;
  };

  const listSelectedToolsForConnector = (connector) => {
    const prefix = `${connector.name}.`;
    return [...allowedTools]
      .filter((toolName) => toolName.startsWith(prefix))
      .sort((a, b) => getToolShortName(a, connector).localeCompare(getToolShortName(b, connector)));
  };

  const ensureCatalogLoaded = async (connectorId) => {
    if (!connectorId || toolCatalogByConnector.has(connectorId)) return;
    const tools = await fetchToolCatalogForConnector(connectorId);
    toolCatalogByConnector.set(connectorId, tools);
  };

  if (effectiveClientId) {
    const policyResponse = await api(`/admin/clients/${effectiveClientId}/policy`);
    const policy = policyResponse.policy || { connectorIds: [], allowedTools: [] };
    selectedConnectorIds = new Set(policy.connectorIds || []);
    allowedTools = new Set(policy.allowedTools || []);
    activeConnectorId = (policy.connectorIds || []).find((id) => getConnectorById(id)) || activeConnectorId;

    for (const connectorId of selectedConnectorIds) {
      await ensureCatalogLoaded(connectorId);
    }
    tokens = (await api(`/admin/clients/${effectiveClientId}/tokens`)).tokens || [];
  }
  recomputeSelectedConnectorsFromAllowedTools();
  await ensureCatalogLoaded(activeConnectorId);

  const renderModal = async () => {
    await ensureCatalogLoaded(activeConnectorId);

    const detailsTabClass = activeTab === 'details' ? 'tab-btn active' : 'tab-btn';
    const accessTabClass = activeTab === 'access' ? 'tab-btn active' : 'tab-btn';
    const tokensTabClass = activeTab === 'tokens' ? 'tab-btn active' : 'tab-btn';

    const connectorChips = sortedConnectors
      .map((connector) => {
        const selectedCount = countSelectedToolsForConnector(connector);
        const classes = ['chip'];
        if (activeConnectorId === connector.id) classes.push('focus');
        if (selectedCount > 0) classes.push('allow');
        const suffix = selectedCount > 0 ? ` (${selectedCount})` : '';
        return `<button class="${classes.join(' ')}" data-connector-focus="${escapeHtml(connector.id)}">${escapeHtml(connector.name)}${suffix}</button>`;
      })
      .join('');

    const activeTools = [...new Set((toolCatalogByConnector.get(activeConnectorId) || []).map((tool) => tool.name))]
      .sort((a, b) => {
        const connector = getConnectorById(activeConnectorId);
        return getToolShortName(a, connector).localeCompare(getToolShortName(b, connector));
      });

    const toolChips = activeTools
      .map((toolName) => {
        const connector = getConnectorById(activeConnectorId);
        const label = getToolShortName(toolName, connector);
        return `<button class="chip ${allowedTools.has(toolName) ? 'allow' : ''}" data-tool="${escapeHtml(toolName)}">${escapeHtml(label)}</button>`;
      })
      .join('');

    const selectedToolGroups = sortedConnectors
      .map((connector) => {
        const names = listSelectedToolsForConnector(connector);
        if (names.length === 0) return '';
        const chips = names
          .map((toolName) => `<button class="chip allow" data-selected-tool="${escapeHtml(toolName)}">${escapeHtml(getToolShortName(toolName, connector))}</button>`)
          .join('');
        return `<div><div class="small" style="margin-bottom:6px;">${escapeHtml(connector.name)}</div><div class="chips">${chips}</div></div>`;
      })
      .filter(Boolean)
      .join('');

    const policyJson = JSON.stringify(
      {
        connectorIds: [...selectedConnectorIds].sort(),
        allowedTools: [...allowedTools].sort(),
        deniedTools: []
      },
      null,
      2
    );

    const tokenList = tokens
      .map(
        (t) => `
      <div class="token-row">
        <div><strong>${escapeHtml(t.tokenPrefix)}</strong> <span class="small">${escapeHtml(fmtDate(t.createdAt))}</span>${t.revokedAt ? ' <span class="small">(revoked)</span>' : ''}</div>
        <button class="secondary" data-revoke-token="${escapeHtml(t.id)}" ${t.revokedAt ? 'disabled' : ''}>Revoke</button>
      </div>`
      )
      .join('');

    const mcpSnippet = lastIssuedToken
      ? JSON.stringify(
          {
            mcpServers: {
              gateway: {
                command: 'npx',
                args: [
                  'mcp-remote',
                  'http://127.0.0.1:3000/mcp',
                  '--header',
                  `Authorization: Bearer ${lastIssuedToken}`
                ]
              }
            }
          },
          null,
          2
        )
      : null;

    openModal(`
      <div class="modal-title">${effectiveClientId ? `Edit Client: ${escapeHtml(formName || '(unnamed)')}` : 'Create Client'}</div>
      <div class="tabs">
        <button class="${detailsTabClass}" data-tab="details">Details</button>
        <button class="${accessTabClass}" data-tab="access">Access</button>
        <button class="${tokensTabClass}" data-tab="tokens">Tokens</button>
      </div>

      <div id="tab-details" style="display:${activeTab === 'details' ? 'block' : 'none'};">
        <label class="label">Name</label>
        <input id="clientName" value="${escapeHtml(formName)}" />
        <label class="label">Description</label>
        <input id="clientDescription" value="${escapeHtml(formDescription)}" />
      </div>

      <div id="tab-access" style="display:${activeTab === 'access' ? 'block' : 'none'};">
        <label class="label">Connectors (select one to browse tools)</label>
        <div class="chips">${connectorChips || '<div class="small">No connectors yet.</div>'}</div>
        <label class="label">Tools ${activeConnectorId ? `for ${escapeHtml(getConnectorById(activeConnectorId)?.name || '')}` : ''}</label>
        <div class="chips">${toolChips || '<div class="small">No tools found for this connector.</div>'}</div>
        <label class="label">Selected Tools</label>
        <div>${selectedToolGroups || '<div class="small">No tools selected yet.</div>'}</div>
        <label class="label">Policy JSON</label>
        <div class="json-panel">${escapeHtml(policyJson)}</div>
      </div>

      <div id="tab-tokens" style="display:${activeTab === 'tokens' ? 'block' : 'none'};">
        <div class="actions" style="justify-content:flex-start; margin-bottom: 8px;">
          <button id="issueTokenBtn" class="primary" ${effectiveClientId ? '' : 'disabled'}>Issue Token</button>
        </div>
        ${effectiveClientId ? '' : '<div class="small" style="margin-bottom:8px;">Save client first, then issue tokens.</div>'}
        <div id="tokenIssueOutput"></div>
        ${mcpSnippet ? `<label class="label">MCP Config</label><div class="json-panel">${escapeHtml(mcpSnippet)}</div>` : ''}
        <div class="token-list">${tokenList || '<div class="small">No tokens issued yet.</div>'}</div>
      </div>

      <div class="actions" style="margin-top: 12px;">
        <div class="small" style="margin-right:auto;">${hasUnsavedChanges ? 'Unsaved Changes' : ''}</div>
        <button id="clientClose" class="secondary">Close</button>
        <button id="clientSave" class="primary">Save</button>
      </div>
      <div id="clientNotice" class="small"></div>
    `);

    document.querySelectorAll('[data-tab]').forEach((btn) => {
      btn.onclick = async () => {
        activeTab = btn.getAttribute('data-tab');
        await renderModal();
      };
    });

    const clientNameEl = document.getElementById('clientName');
    const clientDescriptionEl = document.getElementById('clientDescription');
    if (clientNameEl) {
      clientNameEl.oninput = () => {
        formName = clientNameEl.value;
        hasUnsavedChanges = true;
      };
    }
    if (clientDescriptionEl) {
      clientDescriptionEl.oninput = () => {
        formDescription = clientDescriptionEl.value;
        hasUnsavedChanges = true;
      };
    }

    document.querySelectorAll('[data-connector-focus]').forEach((btn) => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-connector-focus');
        if (!id) return;
        activeConnectorId = id;
        await ensureCatalogLoaded(activeConnectorId);
        await renderModal();
      };
    });

    document.querySelectorAll('[data-tool]').forEach((btn) => {
      btn.onclick = async () => {
        const name = btn.getAttribute('data-tool');
        if (!name) return;
        if (allowedTools.has(name)) {
          allowedTools.delete(name);
        } else {
          allowedTools.add(name);
        }
        recomputeSelectedConnectorsFromAllowedTools();
        hasUnsavedChanges = true;
        await renderModal();
      };
    });

    document.querySelectorAll('[data-selected-tool]').forEach((btn) => {
      btn.onclick = async () => {
        const name = btn.getAttribute('data-selected-tool');
        if (!name) return;
        allowedTools.delete(name);
        recomputeSelectedConnectorsFromAllowedTools();
        hasUnsavedChanges = true;
        await renderModal();
      };
    });

    document.querySelectorAll('[data-revoke-token]').forEach((btn) => {
      btn.onclick = async () => {
        if (!effectiveClientId) return;
        const tokenId = btn.getAttribute('data-revoke-token');
        if (!tokenId) return;
        try {
          await api(`/admin/clients/${effectiveClientId}/tokens/${tokenId}`, { method: 'DELETE' });
          tokens = (await api(`/admin/clients/${effectiveClientId}/tokens`)).tokens || [];
          await renderModal();
        } catch (err) {
          document.getElementById('clientNotice').textContent = err.message;
        }
      };
    });

    const issueTokenBtn = document.getElementById('issueTokenBtn');
    if (issueTokenBtn) {
      issueTokenBtn.onclick = async () => {
        try {
          if (!effectiveClientId) throw new Error('Save client first before issuing token');
          const token = await api(`/admin/clients/${effectiveClientId}/tokens`, { method: 'POST', body: '{}' });
          lastIssuedToken = token.token || null;
          tokens = (await api(`/admin/clients/${effectiveClientId}/tokens`)).tokens || [];
          await renderModal();
          const output = document.getElementById('tokenIssueOutput');
          if (output) {
            output.innerHTML = `<div class="notice"><strong>New Token (shown once)</strong><pre>${escapeHtml(JSON.stringify(token, null, 2))}</pre></div>`;
          }
        } catch (err) {
          const output = document.getElementById('tokenIssueOutput');
          if (output) output.textContent = err.message;
        }
      };
    }

    document.getElementById('clientClose').onclick = closeModal;
    document.getElementById('clientSave').onclick = async () => {
      try {
        if (!formName.trim()) {
          throw new Error('Name is required');
        }

        if (!effectiveClientId) {
          const created = await api('/admin/clients', {
            method: 'POST',
            body: JSON.stringify({ name: formName, description: formDescription })
          });
          effectiveClientId = created.id;
        } else {
          await api(`/admin/clients/${effectiveClientId}`, {
            method: 'PUT',
            body: JSON.stringify({ name: formName, description: formDescription })
          });
        }

        await api(`/admin/clients/${effectiveClientId}/policy`, {
          method: 'PUT',
          body: JSON.stringify({ connectorIds: [...selectedConnectorIds].sort(), allowedTools: [...allowedTools].sort(), deniedTools: [] })
        });
        tokens = (await api(`/admin/clients/${effectiveClientId}/tokens`)).tokens || [];
        hasUnsavedChanges = false;
        await loadDashboard();
        closeModal();
      } catch (err) {
        const notice = document.getElementById('clientNotice');
        notice.textContent = err.message;
        notice.className = 'small';
      }
    };
  };

  await renderModal();
}

function connectorModal(connector) {
  const isNew = !connector;
  const initialTransport = connector?.transport ?? 'http';
  const initialAuthMode =
    connector?.transport === 'stdio' ? 'api_token'
      : connector?.mode === 'oauth_url' ? 'oauth' : 'oauth';

  openModal(`
    <div class="modal-title">${isNew ? 'Create Connector' : 'Edit Connector'}</div>
    <label class="label">Name</label>
    <input id="connectorName" value="${escapeHtml(connector?.name ?? '')}" />
    <label class="label">Transport</label>
    <select id="connectorTransport">
      <option value="http" ${initialTransport === 'http' ? 'selected' : ''}>HTTP</option>
      <option value="stdio" ${initialTransport === 'stdio' ? 'selected' : ''}>STDIO</option>
    </select>
    <div id="httpAuthWrap">
      <label class="label">Auth</label>
      <select id="connectorAuthMode">
        <option value="oauth" ${initialAuthMode === 'oauth' ? 'selected' : ''}>OAuth</option>
        <option value="api_token" ${initialAuthMode === 'api_token' ? 'selected' : ''}>API Token</option>
      </select>
      <label class="label">URL</label>
      <input id="connectorUrl" value="${escapeHtml(typeof connector?.configJson?.url === 'string' ? connector.configJson.url : '')}" />
      <div id="apiTokenWrap">
        <label class="label">API Token</label>
        <input id="connectorApiToken" value="" />
      </div>
    </div>
    <div id="stdioWrap">
      <label class="label">STDIO Config JSON</label>
      <textarea id="connectorStdioConfig">${escapeHtml(JSON.stringify(
        connector?.transport === 'stdio'
          ? connector.configJson
          : { command: '', args: [], cwd: '', env: {} },
        null,
        2
      ))}</textarea>
    </div>
    <label class="label">Config JSON</label>
    <div id="configPreview" class="json-panel"></div>
    <div class="actions" style="margin-top: 14px;">
      <button id="connectorClose" class="secondary">Close</button>
      <button id="connectorSave" class="primary">Save</button>
      <button id="connectorAuthorizeSave" class="primary">Authorize & Save</button>
    </div>
    <div id="connectorNotice" class="small"></div>
  `);

  const transportEl = document.getElementById('connectorTransport');
  const authModeEl = document.getElementById('connectorAuthMode');
  const urlEl = document.getElementById('connectorUrl');
  const apiTokenEl = document.getElementById('connectorApiToken');
  const stdioEl = document.getElementById('connectorStdioConfig');
  const httpAuthWrap = document.getElementById('httpAuthWrap');
  const stdioWrap = document.getElementById('stdioWrap');
  const apiTokenWrap = document.getElementById('apiTokenWrap');
  const configPreview = document.getElementById('configPreview');
  const authorizeSaveBtn = document.getElementById('connectorAuthorizeSave');
  const saveBtn = document.getElementById('connectorSave');

  const computePayload = () => {
    const transport = transportEl.value;
    const name = document.getElementById('connectorName').value;
    let mode = 'json_config';
    let configJson = {};

    if (transport === 'http') {
      const authMode = authModeEl.value;
      const url = urlEl.value;
      if (authMode === 'oauth') {
        mode = 'oauth_url';
        configJson = { url };
      } else {
        mode = 'json_config';
        const token = apiTokenEl.value;
        configJson = {
          url,
          ...(token ? { Authorization: `Bearer ${token}` } : {})
        };
      }
    } else {
      mode = 'json_config';
      configJson = JSON.parse(stdioEl.value);
    }

    return { name, transport, mode, enabled: true, configJson };
  };

  const refreshVisibilityAndPreview = () => {
    const transport = transportEl.value;
    const authMode = authModeEl.value;

    if (transport === 'http') {
      httpAuthWrap.style.display = '';
      stdioWrap.style.display = 'none';
      apiTokenWrap.style.display = authMode === 'api_token' ? '' : 'none';
      authorizeSaveBtn.style.display = authMode === 'oauth' ? '' : 'none';
      saveBtn.style.display = authMode === 'oauth' ? 'none' : '';
    } else {
      httpAuthWrap.style.display = 'none';
      stdioWrap.style.display = '';
      authorizeSaveBtn.style.display = 'none';
      saveBtn.style.display = '';
    }

    try {
      const payload = computePayload();
      configPreview.textContent = JSON.stringify(payload.configJson, null, 2);
    } catch (error) {
      configPreview.textContent = `Invalid config: ${error.message}`;
    }
  };

  const persistConnector = async () => {
    const body = computePayload();
    if (isNew) {
      return api('/admin/connectors', { method: 'POST', body: JSON.stringify(body) });
    }
    return api(`/admin/connectors/${connector.id}`, {
      method: 'PUT',
      body: JSON.stringify(body)
    });
  };

  const setNotice = (message, ok = false) => {
    const notice = document.getElementById('connectorNotice');
    notice.textContent = message;
    notice.className = ok ? 'small success' : 'small';
  };

  transportEl.onchange = refreshVisibilityAndPreview;
  authModeEl.onchange = refreshVisibilityAndPreview;
  urlEl.oninput = refreshVisibilityAndPreview;
  apiTokenEl.oninput = refreshVisibilityAndPreview;
  stdioEl.oninput = refreshVisibilityAndPreview;
  refreshVisibilityAndPreview();

  document.getElementById('connectorClose').onclick = closeModal;

  document.getElementById('connectorSave').onclick = async () => {
    try {
      const saved = await persistConnector();
      const body = computePayload();
      const connectorId = saved.id || connector?.id;
      if (connectorId && body.transport === 'http' && authModeEl.value === 'api_token') {
        await api(`/admin/connectors/${connectorId}/discover`, { method: 'POST', body: '{}' });
      }
      await loadDashboard();
      closeModal();
    } catch (err) {
      setNotice(err.message);
    }
  };

  authorizeSaveBtn.onclick = async () => {
    try {
      const saved = await persistConnector();
      const connectorId = saved.id || connector?.id;
      if (!connectorId) throw new Error('Failed to determine connector id');

      const oauthStart = await api(`/admin/connectors/${connectorId}/oauth/start`, { method: 'POST', body: '{}' });
      window.open(oauthStart.url, '_blank');
      await loadDashboard();
      closeModal();
    } catch (err) {
      setNotice(err.message);
    }
  };
}

window.addEventListener('message', async (event) => {
  if (event.origin !== window.location.origin) return;
  const data = event.data;
  if (!data || data.type !== 'oauth-complete') return;
  await loadDashboard();
  if (data.ok) setError('');
});

cards.addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-act]');
  if (!btn) return;
  const act = btn.dataset.act;
  const id = btn.dataset.id;

  try {
    if (act === 'edit-client') {
      await clientModal(id);
    } else if (act === 'delete-client') {
      await api(`/admin/clients/${id}`, { method: 'DELETE' });
      await loadDashboard();
    } else if (act === 'edit-connector') {
      connectorModal(state.connectors.find((c) => c.id === id));
    } else if (act === 'discover-connector') {
      await api(`/admin/connectors/${id}/discover`, { method: 'POST', body: '{}' });
      await loadDashboard();
    } else if (act === 'delete-connector') {
      await api(`/admin/connectors/${id}`, { method: 'DELETE' });
      await loadDashboard();
    }
  } catch (err) {
    setError(err.message, err.details);
  }
});

createBtn.onclick = () => {
  if (state.page === 'clients') clientModal(null);
  else connectorModal(null);
};

document.getElementById('navClients').onclick = () => {
  state.page = 'clients';
  document.getElementById('navClients').classList.add('active');
  document.getElementById('navConnectors').classList.remove('active');
  render();
};

document.getElementById('navConnectors').onclick = () => {
  state.page = 'connectors';
  document.getElementById('navConnectors').classList.add('active');
  document.getElementById('navClients').classList.remove('active');
  render();
};

document.getElementById('logoutBtn').onclick = async () => {
  await api('/admin/logout', { method: 'POST', body: '{}' });
  location.reload();
};

document.getElementById('loginSubmit').onclick = async () => {
  const loginError = document.getElementById('loginError');
  loginError.textContent = '';
  try {
    await api('/admin/login', {
      method: 'POST',
      body: JSON.stringify({ password: document.getElementById('loginPassword').value })
    });
    await bootstrap();
  } catch (e) {
    loginError.textContent = e.message;
  }
};

async function bootstrap() {
  try {
    await api('/admin/session');
    loginView.classList.add('hidden');
    app.classList.add('ready');
    await loadDashboard();
  } catch {
    loginView.classList.remove('hidden');
    app.classList.remove('ready');
  }
}

bootstrap();
