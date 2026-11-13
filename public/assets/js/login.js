/* Fundo animado da tela de login: rede de nós com pulsos */
(() => {
  const c = document.getElementById('login-bg');
  if (!c) return;
  const ctx = c.getContext('2d');
  const accent = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#00e5ff';
  let W, H, nodes = [];
  const resize = () => {
    W = c.width = innerWidth * devicePixelRatio;
    H = c.height = innerHeight * devicePixelRatio;
    nodes = Array.from({ length: Math.min(70, Math.floor(innerWidth / 22)) }, () => ({
      x: Math.random() * W, y: Math.random() * H, vx: (Math.random() - .5) * .3 * devicePixelRatio, vy: (Math.random() - .5) * .3 * devicePixelRatio,
    }));
  };
  resize();
  addEventListener('resize', resize);
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const draw = () => {
    ctx.clearRect(0, 0, W, H);
    const max = 160 * devicePixelRatio;
    for (const n of nodes) {
      n.x += n.vx; n.y += n.vy;
      if (n.x < 0 || n.x > W) n.vx *= -1;
      if (n.y < 0 || n.y > H) n.vy *= -1;
    }
    for (let i = 0; i < nodes.length; i++) for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j], d = Math.hypot(a.x - b.x, a.y - b.y);
      if (d < max) {
        ctx.strokeStyle = accent;
        ctx.globalAlpha = (1 - d / max) * .25;
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
      }
    }
    ctx.globalAlpha = .8;
    ctx.fillStyle = accent;
    for (const n of nodes) { ctx.beginPath(); ctx.arc(n.x, n.y, 1.6 * devicePixelRatio, 0, 7); ctx.fill(); }
    ctx.globalAlpha = 1;
    if (!reduce) requestAnimationFrame(draw);
  };
  draw();
})();
