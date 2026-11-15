/* DB Oráculo Analyzer — utilidades globais (ES2020, sem build) */
'use strict';

const BASE = document.querySelector('meta[name="base-path"]')?.content || '';
const CSRF = document.querySelector('meta[name="csrf-token"]')?.content || '';

window.api = async function api(path, body, method = 'POST') {
  const opts = { method, headers: { 'X-CSRF-Token': CSRF, 'Accept': 'application/json' }, credentials: 'same-origin' };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(BASE + path, opts);
  let data = {};
  try { data = await res.json(); } catch { data = { error: `HTTP ${res.status}` }; }
  if (res.status === 401) { location.href = BASE + '/login'; }
  if (!res.ok && !data.error) data.error = `HTTP ${res.status}`;
  return data;
};

window.esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

window.animateCount = function (el, to, ms = 900) {
  const from = parseFloat(el.dataset.current || el.textContent.replace(/\D/g, '')) || 0;
  const start = performance.now();
  el.dataset.current = to;
  const step = (t) => {
    const p = Math.min(1, (t - start) / ms);
    const v = from + (to - from) * (1 - Math.pow(1 - p, 3));
    el.textContent = Math.round(v).toLocaleString('pt-BR');
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
};

document.addEventListener('DOMContentLoaded', () => {
  // Sidebar mobile
  document.querySelector('[data-toggle-sidebar]')?.addEventListener('click', () => document.getElementById('sidebar')?.classList.toggle('open'));

  // KPIs animados
  document.querySelectorAll('[data-count]').forEach((el) => animateCount(el, +el.dataset.count));

  // Confirmação de exclusão
  document.addEventListener('submit', (e) => {
    const msg = e.target.dataset?.confirm;
    if (msg && !window.confirm(msg)) e.preventDefault();
  });

  // Copiar blocos de código
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-copy]');
    if (!btn) return;
    const code = btn.parentElement.querySelector('code, pre');
    try {
      await navigator.clipboard.writeText(code.innerText);
      btn.textContent = '✔ Copiado';
      btn.classList.add('done');
      setTimeout(() => { btn.textContent = 'Copiar'; btn.classList.remove('done'); }, 1600);
    } catch { btn.textContent = 'Selecione e copie'; }
  });

  // Abas
  document.querySelectorAll('[data-tabs]').forEach((tabs) => {
    tabs.querySelectorAll('[data-tab]').forEach((b) => b.addEventListener('click', () => {
      tabs.querySelectorAll('[data-tab]').forEach((x) => x.classList.toggle('active', x === b));
      tabs.querySelectorAll('[data-pane]').forEach((p) => p.classList.toggle('active', p.dataset.pane === b.dataset.tab));
      history.replaceState(null, '', '#' + b.dataset.tab);
    }));
    const h = location.hash.slice(1);
    if (h) tabs.querySelector(`[data-tab="${CSS.escape(h)}"]`)?.click();
  });

  // Formulários de IA: placeholders por provedor + teste de conexão
  document.querySelectorAll('[data-ai-form]').forEach((form) => {
    const sel = form.querySelector('select[name=provider]');
    const sync = () => {
      const o = sel.selectedOptions[0];
      form.querySelector('[data-model-input]').placeholder = o.dataset.model + ' (padrão)';
      form.querySelector('[data-base-input]').placeholder = o.dataset.base;
    };
    sel.addEventListener('change', sync);
    sync();
    form.querySelector('[data-ai-test]').addEventListener('click', async (ev) => {
      const out = form.querySelector('[data-ai-result]');
      const btn = ev.currentTarget;
      btn.disabled = true;
      out.className = 'test-result';
      out.textContent = '⏳ Testando…';
      const fd = Object.fromEntries(new FormData(form));
      const r = await api('/api/ai/test', { ...fd, global: form.dataset.global || '' });
      btn.disabled = false;
      if (r.ok) {
        out.className = 'test-result ok';
        out.textContent = `✔ ${r.model} respondeu em ${r.latency_ms} ms: "${r.reply}"`;
      } else {
        out.className = 'test-result err';
        out.textContent = '✘ ' + (r.error || 'Falha');
      }
    });
  });

  // Tabela de usuários com busca em tempo real e paginação
  const ut = document.querySelector('[data-users-table]');
  if (ut) {
    const tpl = ut.querySelector('[data-row-template]');
    const tbody = ut.querySelector('[data-rows]');
    const pager = ut.querySelector('[data-pager]');
    let page = 1, q = '', timer;
    const load = async () => {
      const r = await api(`/api/users?q=${encodeURIComponent(q)}&page=${page}`, undefined, 'GET');
      tbody.innerHTML = '';
      ut.querySelector('[data-total]').textContent = `${r.total} conta(s)`;
      if (!r.rows?.length) tbody.innerHTML = '<tr><td colspan="7" class="muted center">Nenhuma conta encontrada.</td></tr>';
      (r.rows || []).forEach((u) => {
        const tr = tpl.content.firstElementChild.cloneNode(true);
        const set = (f, v) => { tr.querySelector(`[data-f="${f}"]`).textContent = v ?? '—'; };
        set('username', u.username);
        set('display_name', u.display_name || u.email);
        set('role', u.role === 'ADMIN' ? 'ADMINISTRADOR' : 'CLIENTE');
        set('ai_profile', u.ai_profile);
        set('status', +u.is_active ? 'Ativa' : 'Inativa');
        set('last_login_at', u.last_login_at ? u.last_login_at + ' UTC' : 'nunca');
        tr.querySelector('[data-edit]').href = `${BASE}/admin/users?edit=${u.id}`;
        const del = tr.querySelector('[data-delete]');
        if (u.id === r.me) del.remove();
        else {
          del.action = `${BASE}/admin/users/${u.id}/delete`;
          del.dataset.confirm = `Excluir a conta '${u.username}'?`;
        }
        tbody.appendChild(tr);
      });
      pager.innerHTML = '';
      for (let i = 1; i <= r.pages; i++) {
        const b = document.createElement('button');
        b.className = 'btn btn-sm ' + (i === r.page ? 'btn-primary' : 'btn-ghost');
        b.textContent = i;
        b.onclick = () => { page = i; load(); };
        pager.appendChild(b);
      }
    };
    ut.querySelector('[data-search]').addEventListener('input', (e) => {
      clearTimeout(timer);
      timer = setTimeout(() => { q = e.target.value.trim(); page = 1; load(); }, 220);
    });
    load();
  }

  // Comparação de relatórios
  const cmpBtn = document.getElementById('btn-compare');
  if (cmpBtn) {
    const boxes = () => [...document.querySelectorAll('.cmp:checked')];
    document.addEventListener('change', (e) => {
      if (!e.target.classList.contains('cmp')) return;
      if (boxes().length > 2) e.target.checked = false;
      cmpBtn.disabled = boxes().length !== 2;
    });
    cmpBtn.addEventListener('click', () => {
      const [a, b] = boxes().map((x) => x.value);
      location.href = `${cmpBtn.dataset.base}?a=${a}&b=${b}`;
    });
  }
});

/* Análises em andamento: indicador lateral e células ao vivo em Relatórios/Painel */
(() => {
  const pill = document.getElementById('nav-live');
  if (!pill) return;
  const known = new Set([...document.querySelectorAll('[data-live-id]')].map((el) => +el.dataset.liveId));
  let timer = null;
  let reloadAt = 0;

  function paintCell(el, s) {
    const state = s.cancelling ? 'cancelling' : s.queued ? 'queued' : 'running';
    el.dataset.state = state;
    el.style.setProperty('--p', s.percent);
    el.querySelector('.live-txt span').textContent = s.cancelling ? 'Cancelando' : s.queued ? 'Na fila' : s.stage_label;
    el.querySelector('.live-txt b').textContent = s.percent + '%';
    el.querySelector('.live-track i').style.width = s.percent + '%';
  }

  function finishCell(el, f) {
    const tr = el.closest('tr');
    const label = f.error === 'Cancelada pelo usuário' ? 'cancelada' : f.status;
    el.outerHTML = `<span class="status status-${esc(f.status)}" title="${esc(f.error || '')}">${esc(label)}</span>`;
    if (tr) {
      tr.classList.remove('row-live');
      tr.classList.add('row-flash');
    }
    known.delete(f.id);
    reloadAt = Date.now() + 1800; // recarrega para trazer score, exportações e comparação
  }

  async function tick() {
    clearTimeout(timer);
    if (document.hidden) { timer = setTimeout(tick, 5000); return; }
    const r = await api('/api/analyzer/running?ids=' + [...known].join(','), undefined, 'GET').catch(() => null);
    if (r && r.items) {
      const items = r.items;
      pill.hidden = !items.length;
      if (items.length) {
        const s = items[0];
        document.getElementById('nav-live-count').textContent = items.length === 1 ? '1 análise em andamento' : `${items.length} análises em andamento`;
        document.getElementById('nav-live-pct').textContent = s.percent + '%';
        document.getElementById('nav-live-sub').textContent = `#${s.id} · ${s.database}`;
        document.getElementById('nav-live-stage').textContent = s.cancelling ? 'Cancelando' : s.queued ? 'Na fila' : s.stage_label;
        document.getElementById('nav-live-fill').style.width = s.percent + '%';
        pill.href = pill.dataset.base + (items.length === 1 ? '/analyzer?watch=' + s.id : '/reports');
      }
      for (const s of items) {
        document.querySelectorAll(`[data-live-id="${s.id}"]`).forEach((el) => paintCell(el, s));
      }
      for (const f of r.finished || []) {
        document.querySelectorAll(`[data-live-id="${f.id}"]`).forEach((el) => finishCell(el, f));
      }
      if (reloadAt && Date.now() >= reloadAt) { location.reload(); return; }
      if (reloadAt) { timer = setTimeout(tick, Math.max(200, reloadAt - Date.now())); return; }
      timer = setTimeout(tick, items.length ? 2500 : 20000);
      return;
    }
    timer = setTimeout(tick, 8000);
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });
  // Na tela do analisador quem acompanha é o analyzer.js; aqui só o indicador lateral, mais espaçado
  timer = setTimeout(tick, pill.hidden && !known.size ? 20000 : 2500);
})();
