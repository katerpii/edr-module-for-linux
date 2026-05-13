'use strict';

const EVT = {1:'fork', 2:'exec', 3:'exit', 4:'file', 5:'net'};
const SEV = {1:'INFO', 2:'WARN', 3:'HIGH', 4:'CRIT'};

let cy          = null;
let activeTab   = 'graph';
let firstLayout = true;

// ── Cytoscape init ───────────────────────────────────────────────
function initCy() {
  cy = cytoscape({
    container: document.getElementById('cy'),
    style: [
      {
        selector: 'node[type="process"]',
        style: {
          'background-color':  '#161b22',
          'border-width':       2,
          'border-color':       '#30363d',
          'color':              '#8b949e',
          'label':              'data(label)',
          'font-size':          10,
          'text-valign':        'bottom',
          'text-margin-y':      5,
          'width':              34,
          'height':             34,
          'text-wrap':          'none',
        }
      },
      {
        selector: 'node[type="process"][?active]',
        style: {
          'border-color': '#3fb950',
          'border-width':  2,
          'color':        '#e6edf3',
        }
      },
      {
        selector: 'node[type="process"][?alerted]',
        style: {
          'background-color': '#2d1216',
          'border-color':     '#f85149',
          'border-width':      3,
          'color':            '#f85149',
        }
      },
      {
        selector: 'node[type="artifact"]',
        style: {
          'background-color': '#1a1a2e',
          'border-color':     '#d29922',
          'border-width':      2,
          'color':            '#d29922',
          'label':            'data(label)',
          'font-size':         9,
          'shape':            'diamond',
          'width':             26,
          'height':            26,
          'text-valign':      'bottom',
          'text-margin-y':     5,
        }
      },
      {
        selector: 'edge[type="fork"]',
        style: {
          'line-color':           '#30363d',
          'target-arrow-color':   '#30363d',
          'target-arrow-shape':   'triangle',
          'curve-style':          'bezier',
          'width':                 1.5,
          'arrow-scale':           0.8,
        }
      },
      {
        selector: 'edge[type="connect"]',
        style: {
          'line-color':           '#d29922',
          'target-arrow-color':   '#d29922',
          'target-arrow-shape':   'triangle',
          'curve-style':          'bezier',
          'line-style':           'dashed',
          'line-dash-pattern':    [4, 3],
          'width':                 1,
          'arrow-scale':           0.7,
        }
      },
      {
        selector: ':selected',
        style: {
          'border-color': '#ffffff',
          'border-width':  3,
        }
      },
    ],
    layout: { name: 'preset' },
  });

  cy.on('tap', 'node[type="process"]', e => showNodeDetail(e.target.data()));
  cy.on('tap', e => { if (e.target === cy) closeDetail(); });
}

// ── Graph ────────────────────────────────────────────────────────
async function refreshGraph() {
  const res = await apiFetch('/api/graph');
  if (!res) return;

  const empty = document.getElementById('graph-empty');
  if (!res.elements.length) { empty.classList.remove('d-none'); return; }
  empty.classList.add('d-none');

  const existingIds = new Set(cy.elements().map(el => el.id()));
  const incoming    = new Set(res.elements.map(el => el.data.id));

  // remove nodes/edges that no longer exist
  cy.elements().filter(el => !incoming.has(el.id())).remove();

  // add new elements
  const toAdd = res.elements.filter(el => !existingIds.has(el.data.id));
  if (toAdd.length) {
    cy.add(toAdd);
    // 디테일 패널이 열려있으면 layout 자체를 skip — 보던 위치 그대로 유지
    if (document.getElementById('node-detail').classList.contains('d-none')) {
      runLayout();
    }
  }

  // update changed properties (active, alerted)
  res.elements.forEach(el => {
    const node = cy.getElementById(el.data.id);
    if (node.length) node.data(el.data);
  });
}

function runLayout() {
  // find process roots: nodes with no incoming fork edges
  const forkTargets = new Set(
    cy.edges('[type="fork"]').map(e => e.target().id())
  );
  const roots = cy.nodes('[type="process"]').filter(n => !forkTargets.has(n.id()));

  cy.layout({
    name:          'breadthfirst',
    directed:       true,
    roots:          roots.length ? roots : undefined,
    padding:        40,
    spacingFactor:  1.5,
    avoidOverlap:   true,
    fit:            firstLayout,  // 첫 로드만 전체 fit, 이후엔 zoom/pan 유지
  }).run();
  firstLayout = false;
}

// ── Node detail ──────────────────────────────────────────────────
async function showNodeDetail(data) {
  const panel   = document.getElementById('node-detail');
  const content = document.getElementById('node-detail-content');

  const ts = fmtTs(data.start_ts);
  content.innerHTML = `
    <div class="detail-row"><span class="detail-key">PID</span>    <span class="detail-val">${data.pid}</span></div>
    <div class="detail-row"><span class="detail-key">Comm</span>   <span class="detail-val">${data.comm || '?'}</span></div>
    <div class="detail-row"><span class="detail-key">Exe</span>    <span class="detail-val" title="${data.exe || ''}">${data.exe || '–'}</span></div>
    <div class="detail-row"><span class="detail-key">Start</span>  <span class="detail-val">${ts}</span></div>
    <div class="detail-row"><span class="detail-key">Status</span> <span class="detail-val">${data.active ? '<span class="text-success">active</span>' : '<span class="text-secondary">exited</span>'}</span></div>
    <button class="btn btn-sm btn-outline-info w-100 mt-3"
            onclick="showAncestry(${data.pid}, ${data.start_ts})">
      ↑ Show Ancestry
    </button>
    <div class="mt-3 mb-2" style="color:#8b949e;font-size:0.7rem;font-weight:700;letter-spacing:.08em">RECENT EVENTS</div>
    <div id="proc-events-list"><span class="text-secondary">loading…</span></div>
  `;
  panel.classList.remove('d-none');

  const evs = await apiFetch(`/api/process/${data.pid}/${data.start_ts}/events`);
  const list = document.getElementById('proc-events-list');
  if (!list) return;

  if (!evs || !evs.length) {
    list.innerHTML = '<div class="text-secondary">no events</div>';
    return;
  }

  list.innerHTML = evs.map(e => `
    <div class="event-item">
      <span class="text-info">${EVT[e.type] || e.type}</span>
      ${e.fn  ? `<span class="ms-1 mono">${e.fn.slice(-40)}</span>` : ''}
      ${e.cmd ? `<div class="mt-1 text-secondary">${e.cmd.substring(0, 70)}</div>` : ''}
    </div>
  `).join('');
}

// ── Ancestry modal ───────────────────────────────────────────────
let ancestryModal = null;

async function showAncestry(pid, start_ts) {
  const body = document.getElementById('ancestry-body');
  body.innerHTML = '<div class="text-secondary text-center">loading…</div>';

  if (!ancestryModal)
    ancestryModal = new bootstrap.Modal(document.getElementById('ancestry-modal'));
  ancestryModal.show();

  const chain = await apiFetch(`/api/graph/ancestry/${pid}/${start_ts}`);
  if (!chain || !chain.length) {
    body.innerHTML = '<div class="text-secondary text-center">No ancestry data</div>';
    return;
  }

  // alerted pids for highlighting
  const alertedPids = new Set(
    (await apiFetch('/api/alerts') || []).map(a => `${a.pid}_${a.start_ts}`)
  );

  const items = chain.map((p, i) => {
    const isRoot   = i === 0;
    const isTarget = i === chain.length - 1;
    const isAlerted = alertedPids.has(`${p.pid}_${p.start_ts}`);
    const cls = isAlerted ? 'anc-alerted' : isTarget ? 'anc-target' : isRoot ? 'anc-root' : '';
    const label = isRoot ? 'root' : isTarget ? 'target' : '';

    return `
      ${i > 0 ? `
        <div class="anc-connector">
          <div class="line"></div>
          <div class="arrow"></div>
        </div>` : ''}
      <div class="anc-card ${cls}"
           onclick="focusProcess(${p.pid}, ${p.start_ts}); ancestryModal.hide()">
        <span class="anc-depth">${label || `d-${p.depth}`}</span>
        <div class="anc-comm">${p.comm || '?'}</div>
        <div class="anc-exe">${p.exe || '–'}</div>
        <div class="anc-pid">pid ${p.pid}</div>
      </div>
    `;
  }).join('');

  body.innerHTML = `<div class="anc-chain">${items}</div>`;
}

function closeDetail() {
  document.getElementById('node-detail').classList.add('d-none');
  cy && cy.elements().unselect();
}

// ── Alerts ───────────────────────────────────────────────────────
async function refreshAlerts() {
  const alerts = await apiFetch('/api/alerts');
  if (!alerts) return;

  document.getElementById('alert-count').textContent   = alerts.length;
  document.getElementById('stat-alerts').textContent   = alerts.length;

  document.getElementById('alert-list').innerHTML =
    alerts.length
      ? alerts.map(a => `
          <div class="alert-item sev-${a.severity}" onclick="focusProcess(${a.pid},${a.start_ts})">
            <div class="rule-id">${a.rule_id}</div>
            <div class="meta">${a.comm || '?'} (pid ${a.pid})</div>
            ${a.fn ? `<div class="meta mono">${a.fn.slice(-36)}</div>` : ''}
            <div class="meta">${fmtTs(a.ts)}</div>
          </div>`).join('')
      : '<div class="px-3 py-2 text-secondary" style="font-size:.78rem">No alerts</div>';
}

// ── Events table ─────────────────────────────────────────────────
async function refreshEvents() {
  const events = await apiFetch('/api/events?limit=200');
  if (!events) return;

  document.getElementById('events-tbody').innerHTML = events.map(e => `
    <tr>
      <td class="text-secondary">${fmtTs(e.ts)}</td>
      <td><span class="badge bg-secondary">${EVT[e.type] || e.type}</span></td>
      <td class="mono">${e.pid}</td>
      <td>${e.comm || '–'}</td>
      <td class="mono truncate" title="${e.fn || ''}">${e.fn || '–'}</td>
      <td class="mono truncate text-secondary" title="${e.cmd || ''}">${e.cmd || '–'}</td>
    </tr>`).join('');
}

// ── Processes table ──────────────────────────────────────────────
async function refreshProcesses() {
  const procs = await apiFetch('/api/processes');
  if (!procs) return;

  document.getElementById('stat-procs').textContent =
    procs.filter(p => !p.end_ts).length;

  document.getElementById('processes-tbody').innerHTML = procs.map(p => `
    <tr class="${p.end_ts ? 'text-secondary' : ''}">
      <td class="mono">${p.pid}</td>
      <td class="mono">${p.ppid || '–'}</td>
      <td>${p.comm || '–'}</td>
      <td class="mono truncate" title="${p.exe || ''}">${p.exe || '–'}</td>
      <td>${p.uid}</td>
      <td>${p.end_ts
        ? '<span class="text-secondary">exited</span>'
        : '<span class="text-success">●</span>'}</td>
    </tr>`).join('');
}

// ── Stats ────────────────────────────────────────────────────────
async function refreshStats() {
  const s = await apiFetch('/api/stats');
  if (!s) return;
  document.getElementById('stat-procs').textContent  = s.active_procs;
  document.getElementById('stat-events').textContent = s.total_events;
  // alerts는 refreshAlerts가 담당
}

// ── Utilities ────────────────────────────────────────────────────
function fmtTs(ns) {
  if (!ns) return '–';
  return new Date(ns / 1e6).toLocaleTimeString();
}

async function apiFetch(url) {
  try {
    const res = await fetch(url);
    return res.ok ? res.json() : null;
  } catch { return null; }
}

function focusProcess(pid, start_ts) {
  setTab('graph');
  const node = cy.getElementById(`p_${pid}_${start_ts}`);
  if (node.length) {
    cy.animate({ center: { eles: node }, zoom: 2 }, { duration: 350 });
    node.select();
    showNodeDetail(node.data());
  }
}

// ── Status indicator ─────────────────────────────────────────────
async function checkStatus() {
  const ok = await apiFetch('/api/stats');
  document.getElementById('status-dot').innerHTML = ok
    ? '● <span class="text-success">live</span>'
    : '● <span class="text-danger">disconnected</span>';
}

// ── Tab switching ─────────────────────────────────────────────────
function setTab(name) {
  activeTab = name;
  document.querySelectorAll('[data-tab]').forEach(el =>
    el.classList.toggle('active', el.dataset.tab === name)
  );
  document.querySelectorAll('.tab-pane').forEach(el =>
    el.classList.toggle('d-none', el.id !== `tab-${name}`)
  );
  if (name === 'graph')     refreshGraph();
  if (name === 'events')    refreshEvents();
  if (name === 'processes') refreshProcesses();
}

// ── Boot ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initCy();

  document.querySelectorAll('[data-tab]').forEach(el =>
    el.addEventListener('click', e => { e.preventDefault(); setTab(el.dataset.tab); })
  );

  checkStatus();
  refreshStats();
  refreshAlerts();
  refreshGraph();

  setInterval(() => {
    checkStatus();
    refreshStats();
    refreshAlerts();
    if (activeTab === 'graph')     refreshGraph();
    if (activeTab === 'events')    refreshEvents();
    if (activeTab === 'processes') refreshProcesses();
  }, 5000);
});
