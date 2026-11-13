/* DB Oráculo Analyzer — interface animada de conexão e varredura (Canvas 2D, sem dependências) */
'use strict';

(() => {
  const form = document.getElementById('conn-form');
  if (!form) return;

  const $ = (s) => document.querySelector(s);
  const canvas = $('#scan-canvas');
  const ctx = canvas.getContext('2d');
  const overlay = $('#scan-overlay');
  const term = $('#terminal');
  const accent = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#00e5ff';
  const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ------------------------------------------------------------------ */
  /* Cena                                                                */
  /* ------------------------------------------------------------------ */
  const scene = {
    phase: 'idle',        // idle | connecting | connected | scanning | ai | done | error
    engine: 'postgresql',
    pulses: [],
    nodes: [],
    edges: [],
    beam: 0,
    t: 0,
    shake: 0,
    W: 0, H: 0, dpr: 1,
  };

  function resize() {
    const r = canvas.getBoundingClientRect();
    scene.dpr = Math.min(2, devicePixelRatio || 1);
    scene.W = r.width;
    scene.H = r.height;
    canvas.width = r.width * scene.dpr;
    canvas.height = r.height * scene.dpr;
    ctx.setTransform(scene.dpr, 0, 0, scene.dpr, 0, 0);
    layoutNodes();
  }
  addEventListener('resize', resize);

  const P = () => ({
    server: { x: scene.W * 0.09, y: scene.H * 0.5 },
    db: { x: scene.W * 0.27, y: scene.H * 0.5 },
    graph: { x0: scene.W * 0.38, x1: scene.W * 0.97, y0: scene.H * 0.1, y1: scene.H * 0.9 },
    ai: { x: scene.W * 0.67, y: scene.H * 0.5 },
  });

  function setPhase(p, label) {
    scene.phase = p;
    overlay.textContent = label || {
      idle: 'Aguardando conexão…', connecting: '⟲ Handshake em andamento', connected: '● Conectado',
      scanning: '⟟ Varredura profunda', ai: '◈ Consultando IA', done: '✔ Laudo gerado', error: '✘ Falha',
    }[p];
    overlay.style.color = p === 'error' ? '#f44336' : p === 'done' ? '#2ee59d' : accent;
  }

  function spawnPulse(dir = 1, color = accent) {
    scene.pulses.push({ p: dir > 0 ? 0 : 1, dir, speed: 0.012 + Math.random() * 0.01, color });
  }

  function setGraph(graph) {
    const idx = new Map();
    const maxSize = Math.max(1, ...graph.nodes.map((n) => n.size));
    scene.nodes = graph.nodes.map((n, i) => {
      idx.set(n.id, i);
      return { ...n, r: 4 + 10 * Math.sqrt(n.size / maxSize), born: scene.t + i * 3, hit: 0, x: 0, y: 0, tx: 0, ty: 0 };
    });
    scene.edges = graph.edges.map((e) => [idx.get(e.from), idx.get(e.to)]).filter(([a, b]) => a !== undefined && b !== undefined);
    layoutNodes(true);
  }

  // Layout em espiral de Fermat com relaxamento simples por FKs
  function layoutNodes(initial = false) {
    if (!scene.nodes.length || !scene.W) return;
    const g = P().graph;
    const cx = (g.x0 + g.x1) / 2, cy = (g.y0 + g.y1) / 2;
    const rx = (g.x1 - g.x0) / 2, ry = (g.y1 - g.y0) / 2;
    const N = scene.nodes.length;
    scene.nodes.forEach((n, i) => {
      const a = i * 2.39996;
      const d = Math.sqrt((i + 0.5) / N);
      n.tx = cx + Math.cos(a) * d * rx * 0.92;
      n.ty = cy + Math.sin(a) * d * ry * 0.92;
    });
    for (let it = 0; it < 40; it++) {
      for (const [a, b] of scene.edges) {
        const A = scene.nodes[a], B = scene.nodes[b];
        const dx = B.tx - A.tx, dy = B.ty - A.ty;
        A.tx += dx * 0.02; A.ty += dy * 0.02; B.tx -= dx * 0.02; B.ty -= dy * 0.02;
      }
    }
    if (initial) scene.nodes.forEach((n) => { const s = P().db; n.x = s.x; n.y = s.y; });
  }

  /* ---------- desenho ---------- */
  function glow(color, blur) { ctx.shadowColor = color; ctx.shadowBlur = blur; }

  function drawServer(x, y) {
    ctx.save();
    glow(accent, 12);
    ctx.strokeStyle = accent;
    ctx.lineWidth = 1.6;
    for (let i = 0; i < 3; i++) {
      const yy = y - 30 + i * 21;
      ctx.strokeRect(x - 26, yy, 52, 17);
      ctx.fillStyle = (Math.floor(scene.t / 12) + i) % 3 === 0 ? '#2ee59d' : '#1e2636';
      ctx.beginPath(); ctx.arc(x + 17, yy + 8.5, 2.5, 0, 7); ctx.fill();
      ctx.fillStyle = accent;
      ctx.fillRect(x - 20, yy + 7, 22, 2.5);
    }
    ctx.restore();
    label('ANALYZER', x, y + 46);
  }

  function drawCylinder(x, y) {
    const w = 38, h = 58, ry = 10;
    const col = scene.phase === 'error' ? '#f44336' : scene.phase === 'idle' ? '#3a4760' : accent;
    ctx.save();
    glow(col, scene.phase === 'connecting' ? 18 + 10 * Math.sin(scene.t / 5) : 14);
    ctx.strokeStyle = col;
    ctx.fillStyle = '#0b0e14';
    ctx.lineWidth = 1.8;
    ctx.beginPath();
    ctx.ellipse(x, y + h / 2, w, ry, 0, 0, Math.PI);
    ctx.lineTo(x - w, y - h / 2);
    ctx.ellipse(x, y - h / 2, w, ry, 0, Math.PI, 0, true);
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
    ctx.beginPath(); ctx.ellipse(x, y - h / 2, w, ry, 0, 0, Math.PI * 2); ctx.stroke();
    for (const k of [-0.1, 0.25]) { ctx.globalAlpha = 0.45; ctx.beginPath(); ctx.ellipse(x, y + h * k, w, ry, 0, 0, Math.PI); ctx.stroke(); }
    ctx.restore();
    label({ postgresql: 'POSTGRESQL', mysql: 'MYSQL', mariadb: 'MARIADB' }[scene.engine], x, y + h / 2 + 28);
  }

  function label(text, x, y) {
    ctx.save();
    ctx.font = '600 10px ui-monospace, Menlo, monospace';
    ctx.fillStyle = '#7d8aa3';
    ctx.textAlign = 'center';
    ctx.fillText(text, x, y);
    ctx.restore();
  }

  function drawLink(a, b) {
    ctx.save();
    const active = !['idle', 'error'].includes(scene.phase);
    ctx.strokeStyle = scene.phase === 'error' ? '#f44336' : active ? accent : '#2a3448';
    ctx.globalAlpha = active ? 0.5 : 0.6;
    ctx.lineWidth = 1.4;
    ctx.setLineDash(scene.phase === 'connecting' || scene.phase === 'idle' ? [6, 6] : []);
    ctx.lineDashOffset = -scene.t;
    ctx.beginPath(); ctx.moveTo(a.x + 30, a.y); ctx.lineTo(b.x - 40, b.y); ctx.stroke();
    ctx.restore();

    // pulsos luminosos
    scene.pulses = scene.pulses.filter((p) => (p.p += p.speed * p.dir) >= 0 && p.p <= 1);
    for (const p of scene.pulses) {
      const x = a.x + 30 + (b.x - 40 - a.x - 30) * p.p;
      ctx.save();
      glow(p.color, 16);
      ctx.fillStyle = p.color;
      ctx.beginPath(); ctx.arc(x, a.y, 3.2, 0, 7); ctx.fill();
      ctx.globalAlpha = 0.35;
      ctx.fillRect(x - 18 * p.dir, a.y - 1, 18 * p.dir, 2);
      ctx.restore();
    }
  }

  function drawGraph() {
    if (!scene.nodes.length) return;
    const g = P().graph;
    const db = P().db;
    const scanning = scene.phase === 'scanning';
    // feixe de leitura (varredura horizontal)
    if (scanning) {
      scene.beam = (scene.beam + 2.2) % (g.x1 - g.x0 + 80);
      const bx = g.x0 - 40 + scene.beam;
      const grad = ctx.createLinearGradient(bx - 70, 0, bx, 0);
      grad.addColorStop(0, 'rgba(0,229,255,0)');
      grad.addColorStop(1, 'rgba(0,229,255,0.16)');
      ctx.fillStyle = grad;
      ctx.fillRect(bx - 70, g.y0 - 10, 70, g.y1 - g.y0 + 20);
      ctx.save(); glow(accent, 14); ctx.strokeStyle = accent; ctx.globalAlpha = 0.85;
      ctx.beginPath(); ctx.moveTo(bx, g.y0 - 10); ctx.lineTo(bx, g.y1 + 10); ctx.stroke(); ctx.restore();
      for (const n of scene.nodes) if (Math.abs(n.x - bx) < 6) n.hit = 1;
    }
    // arestas (FKs)
    ctx.save();
    ctx.lineWidth = 1;
    for (const [a, b] of scene.edges) {
      const A = scene.nodes[a], B = scene.nodes[b];
      if (scene.t < Math.max(A.born, B.born)) continue;
      ctx.strokeStyle = accent;
      ctx.globalAlpha = 0.18 + 0.4 * Math.max(A.hit, B.hit);
      ctx.beginPath(); ctx.moveTo(A.x, A.y); ctx.lineTo(B.x, B.y); ctx.stroke();
    }
    ctx.restore();
    // nós (tabelas)
    const ai = P().ai;
    for (const n of scene.nodes) {
      if (scene.t < n.born) continue;
      const age = Math.min(1, (scene.t - n.born) / 25);
      let tx = n.tx, ty = n.ty;
      if (scene.phase === 'ai') {
        const ang = Math.atan2(n.ty - ai.y, n.tx - ai.x) + scene.t / 160;
        const d = Math.hypot(n.tx - ai.x, n.ty - ai.y) * (0.55 + 0.1 * Math.sin(scene.t / 20 + n.r));
        tx = ai.x + Math.cos(ang) * d; ty = ai.y + Math.sin(ang) * d;
      }
      n.x += (tx - n.x) * 0.08; n.y += (ty - n.y) * 0.08;
      if (scene.t - n.born < 25) { // trilha de expansão a partir do cilindro
        ctx.save(); ctx.strokeStyle = accent; ctx.globalAlpha = 0.25 * (1 - age);
        ctx.beginPath(); ctx.moveTo(db.x + 40, db.y); ctx.lineTo(n.x, n.y); ctx.stroke(); ctx.restore();
      }
      n.hit *= 0.96;
      const col = scene.phase === 'done' ? '#2ee59d' : n.pk ? accent : '#ff9800';
      ctx.save();
      glow(col, 6 + 14 * n.hit);
      ctx.fillStyle = '#0b0e14';
      ctx.strokeStyle = col;
      ctx.lineWidth = 1.5;
      ctx.globalAlpha = age;
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r * (0.4 + 0.6 * age) * (1 + 0.25 * n.hit), 0, 7); ctx.fill(); ctx.stroke();
      if (n.hit > 0.3 || n.r > 10) {
        ctx.shadowBlur = 0;
        ctx.font = '9px ui-monospace, Menlo, monospace';
        ctx.fillStyle = '#9fb3cc';
        ctx.fillText(n.label.slice(0, 18), n.x + n.r + 3, n.y + 3);
      }
      ctx.restore();
    }
    if (scene.phase === 'ai') {
      ctx.save();
      const r = 18 + 4 * Math.sin(scene.t / 8);
      glow('#b388ff', 30);
      ctx.strokeStyle = '#b388ff';
      ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(ai.x, ai.y, r, 0, 7); ctx.stroke();
      ctx.beginPath(); ctx.arc(ai.x, ai.y, r * 0.45, 0, 7); ctx.fillStyle = '#b388ff'; ctx.fill();
      ctx.restore();
      label('IA', ai.x, ai.y + r + 16);
    }
  }

  function frame() {
    scene.t++;
    ctx.clearRect(0, 0, scene.W, scene.H);
    // grade de fundo
    ctx.save(); ctx.strokeStyle = '#121a27'; ctx.lineWidth = 1;
    for (let x = (scene.t * 0.2) % 32; x < scene.W; x += 32) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, scene.H); ctx.stroke(); }
    for (let y = 0; y < scene.H; y += 32) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(scene.W, y); ctx.stroke(); }
    ctx.restore();

    const p = P();
    const sx = scene.shake > 0 ? (Math.random() - 0.5) * scene.shake : 0;
    scene.shake *= 0.9;
    ctx.save(); ctx.translate(sx, 0);
    if (scene.phase === 'connecting' && scene.t % 9 === 0) spawnPulse(1);
    if (scene.phase === 'connecting' && scene.t % 23 === 0) spawnPulse(-1, '#2ee59d');
    if (['connected', 'scanning', 'ai'].includes(scene.phase) && scene.t % 28 === 0) spawnPulse(Math.random() > 0.5 ? 1 : -1);
    drawLink(p.server, p.db);
    drawServer(p.server.x, p.server.y);
    drawCylinder(p.db.x, p.db.y);
    drawGraph();
    ctx.restore();
    if (!reduceMotion || scene.t % 10 === 0) requestAnimationFrame(frame);
    else setTimeout(() => requestAnimationFrame(frame), 160);
  }

  /* ------------------------------------------------------------------ */
  /* Terminal, odômetros e etapas                                        */
  /* ------------------------------------------------------------------ */
  const queue = [];
  let typing = false;
  function out(text, cls = '') {
    queue.push([text, cls]);
    if (!typing) flush();
  }
  function flush() {
    typing = queue.length > 0;
    if (!typing) return;
    const [text, cls] = queue.shift();
    const div = document.createElement('div');
    const auto = text.startsWith('✔') ? 't-ok' : text.startsWith('⚠') ? 't-warn' : text.startsWith('✘') ? 't-err' : text.startsWith('→') || text.startsWith('•') ? 't-acc' : '';
    div.className = 't-line ' + (cls || auto);
    div.textContent = text;
    term.appendChild(div);
    while (term.children.length > 400) term.firstChild.remove();
    term.scrollTop = term.scrollHeight;
    setTimeout(flush, queue.length > 40 ? 6 : 28);
  }
  const waitTerminal = () => new Promise((res) => { const chk = () => (typing ? setTimeout(chk, 50) : res()); chk(); });

  const odo = (k) => document.querySelector(`[data-odo="${k}"]`);
  const counters = { tables: 0, indexes: 0, fks: 0, findings: 0 };
  function bump(k, v) {
    counters[k] = v;
    animateCount(odo(k), v);
  }

  function stageEl(k) { return document.querySelector(`#stages [data-stage="${k}"]`); }
  function resetStages() {
    document.querySelectorAll('#stages li').forEach((li) => { li.className = ''; li.querySelector('.st-time').textContent = ''; });
    Object.keys(counters).forEach((k) => { counters[k] = 0; odo(k).textContent = '0'; odo(k).dataset.current = 0; });
    odo('score').textContent = '—';
  }

  /* ------------------------------------------------------------------ */
  /* Fluxo                                                               */
  /* ------------------------------------------------------------------ */
  const btnList = $('#btn-list');
  const btnStart = $('#btn-start');
  const dbSelect = $('#db-select');
  const status = $('#conn-status');

  form.querySelectorAll('input[name=engine]').forEach((r) => r.addEventListener('change', () => {
    form.port.value = r.dataset.port;
    scene.engine = r.value;
  }));

  function payload() {
    const fd = new FormData(form);
    const o = Object.fromEntries(fd);
    o.dedicated = fd.has('dedicated');
    return o;
  }

  btnList.addEventListener('click', async () => {
    if (!form.host.value || !form.username.value) { form.reportValidity(); return; }
    const data = payload();
    scene.engine = data.engine;
    scene.nodes = []; scene.edges = [];
    setPhase('connecting');
    btnList.disabled = true;
    btnStart.disabled = true;
    status.className = 'test-result';
    status.textContent = '⏳ Validando credenciais…';
    out(`oraculo@analyzer:~$ connect --engine=${data.engine} ${data.username}@${data.host}:${data.port} --ssl=${data.ssl} --read-only`, 't-dim');
    const t0 = performance.now();
    const r = await api('/api/analyzer/databases', data);
    await new Promise((res) => setTimeout(res, Math.max(0, 900 - (performance.now() - t0)))); // deixa o handshake visível
    btnList.disabled = false;
    if (!r.ok) {
      setPhase('error');
      scene.shake = 14;
      status.className = 'test-result err';
      status.textContent = '✘ ' + r.error;
      out('✘ ' + r.error);
      return;
    }
    setPhase('connected', `● Conectado · ${r.latency_ms} ms`);
    animateCount(odo('latency'), r.latency_ms);
    status.className = 'test-result ok';
    status.textContent = `✔ ${r.databases.length} banco(s) disponíveis · handshake em ${r.latency_ms} ms`;
    out(`✔ Handshake concluído em ${r.latency_ms} ms — ${r.databases.length} banco(s) visíveis`);
    dbSelect.innerHTML = '<option value="">— selecione —</option>' + r.databases.map((d) => `<option value="${esc(d.name)}">${esc(d.name)} (${esc(d.size)})</option>`).join('');
    dbSelect.disabled = false;
    if (r.connected_db && r.connected_db !== 'postgres') {
      out(`• Conexão inicial feita no banco "${r.connected_db}" (restrição de pg_hba)`);
      if ([...dbSelect.options].some((o) => o.value === r.connected_db)) { dbSelect.value = r.connected_db; btnStart.disabled = false; }
    }
    form.password.value = ''; // não mantém a senha no DOM após validar
  });

  dbSelect.addEventListener('change', () => { btnStart.disabled = !dbSelect.value; });

  /* ---------- SSH (opcional) ---------- */
  const sshOn = $('#ssh-enabled');
  const sshFields = $('#ssh-fields');
  const sshStatus = $('#ssh-status');
  const btnSsh = $('#btn-ssh');
  let sshTested = false;
  const syncSsh = () => {
    sshFields.hidden = !sshOn.checked;
    const mode = form.ssh_auth.value;
    form.querySelectorAll('[data-ssh]').forEach((el) => { el.hidden = el.dataset.ssh !== mode; });
  };
  sshOn.addEventListener('change', syncSsh);
  form.ssh_auth.addEventListener('change', syncSsh);
  syncSsh();
  ['ssh_host', 'ssh_port', 'ssh_user', 'ssh_auth'].forEach((n) => form[n].addEventListener('change', () => { sshTested = false; }));

  btnSsh.addEventListener('click', async () => {
    if (!form.ssh_user.value) { form.ssh_user.focus(); return; }
    btnSsh.disabled = true;
    sshStatus.className = 'test-result';
    sshStatus.textContent = '⏳ Conectando via SSH…';
    const target = `${form.ssh_user.value}@${form.ssh_host.value || form.host.value || '?'}:${form.ssh_port.value || 22}`;
    out(`oraculo@analyzer:~$ ssh ${target} --read-only --detect-hardware`, 't-dim');
    const r = await api('/api/analyzer/ssh', payload());
    btnSsh.disabled = false;
    if (!r.ok) {
      sshTested = false;
      sshStatus.className = 'test-result err';
      sshStatus.textContent = '✘ ' + r.error;
      out('✘ ' + r.error);
      return;
    }
    sshTested = true;
    const hw = r.hardware || {};
    if (hw.vcpu) form.vcpu.value = hw.vcpu;
    if (hw.clock_ghz) form.clock_ghz.value = String(hw.clock_ghz).replace('.', ',');
    if (hw.ram_gb) form.ram_gb.value = String(hw.ram_gb).replace('.', ',');
    if (hw.disk) form.disk.value = hw.disk;
    const i = r.info || {};
    sshStatus.className = 'test-result ok';
    sshStatus.textContent = `✔ SSH ok em ${r.latency_ms} ms · ${[hw.vcpu && hw.vcpu + ' vCPU', i.ram && i.ram + ' RAM', hw.disk && hw.disk.toUpperCase(), i.virt].filter(Boolean).join(' · ')} — hardware preenchido`;
    out(`✔ SSH ok · ${i.kernel || ''}`);
    if (i.cpu) out(`  ↳ ${i.cpu}`, 't-dim');
    if (r.fingerprint) out(`  ↳ host key fixada: ${r.fingerprint}`, 't-dim');
    form.ssh_password.value = ''; form.ssh_key.value = ''; form.ssh_passphrase.value = ''; // não mantém segredos no DOM
  });

  btnStart.addEventListener('click', async () => {
    const data = payload();
    if (!data.database) return;
    btnStart.disabled = true;
    btnList.disabled = true;
    resetStages();
    out(`oraculo@analyzer:~$ analyze --database=${data.database} --safe-mode`, 't-dim');
    if (data.ssh_enabled && !sshTested && !data.ssh_password && !data.ssh_key) {
      out('✘ Coleta via SSH marcada: informe a senha/chave SSH ou clique em "Testar SSH".');
      btnStart.disabled = false; btnList.disabled = false;
      return;
    }
    const s = await api('/api/analyzer/start', data);
    if (s.error) { out('✘ ' + s.error); btnList.disabled = false; return; }

    for (const stage of Object.keys(s.stages)) {
      const li = stageEl(stage);
      li.className = 'running';
      out(`→ [${s.stages[stage]}]`);
      if (stage === 'connect') setPhase('connecting', '⟲ Reconectando em modo somente leitura');
      if (['schemas', 'indexes', 'queries', 'sizing', 'os'].includes(stage)) setPhase('scanning', '⟟ ' + s.stages[stage]);
      if (stage === 'ai') setPhase('ai');
      if (stage === 'report') setPhase('scanning', '✎ Gerando laudo técnico');

      const t0 = performance.now();
      const r = await api('/api/analyzer/step', { id: s.id, stage });
      if (r.error) {
        li.className = 'error';
        setPhase('error');
        scene.shake = 14;
        out('✘ ' + r.error);
        btnList.disabled = false;
        btnStart.disabled = false;
        return;
      }
      const lines = r.log || [];
      lines.slice(0, 120).forEach((l) => out(l));
      if (lines.length > 120) out(`  … +${lines.length - 120} linhas`, 't-dim');

      const c = r.counters || {};
      if (c.tables !== undefined) bump('tables', c.tables);
      if (c.fks !== undefined) bump('fks', c.fks);
      if (c.indexes !== undefined) bump('indexes', c.indexes);
      if (r.findings) bump('findings', counters.findings + r.findings);
      if (c.score !== undefined) animateCount(odo('score'), c.score);
      if (stage === 'connect') setPhase('connected');
      if (r.graph) setGraph(r.graph);

      await waitTerminal();
      // ritmo mínimo por etapa para que a varredura seja legível mesmo em bancos pequenos
      const minMs = stage === 'schemas' ? 2600 : 1100;
      await new Promise((res) => setTimeout(res, Math.max(0, minMs - (performance.now() - t0))));
      li.className = 'done';
      li.querySelector('.st-time').textContent = (r.elapsed_ms / 1000).toFixed(1) + 's';

      if (stage === 'report') {
        setPhase('done');
        out(`✔ Concluído. Abrindo laudo…`);
        setTimeout(() => { location.href = r.url; }, 2200);
      }
    }
  });

  resize();
  frame();
})();
