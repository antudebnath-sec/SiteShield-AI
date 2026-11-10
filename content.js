(() => {
  function collect() {
    const forms = [...document.forms].slice(0, 20).map((f) => ({
      action: f.getAttribute('action') || '', method: (f.getAttribute('method') || 'get').toLowerCase(),
      pw: !!f.querySelector('input[type=password]')
    }));
    const links = [...document.querySelectorAll('a[href]')].slice(0, 300).map((a) => ({
      href: a.getAttribute('href'), text: (a.textContent || '').trim().slice(0, 100)
    }));
    let hiddenIframes = 0;
    document.querySelectorAll('iframe').forEach((i) => {
      const r = i.getBoundingClientRect(), s = getComputedStyle(i);
      if (r.width <= 2 || r.height <= 2 || s.display === 'none' || s.visibility === 'hidden') hiddenIframes++;
    });
    let obf = 0;
    document.querySelectorAll('script:not([src])').forEach((s) => {
      obf += ((s.textContent || '').slice(0, 200000).match(/eval\(|atob\(|unescape\(|fromCharCode|document\.write\(/g) || []).length;
    });
    let metaRefresh = null;
    const m = document.querySelector('meta[http-equiv="refresh" i]');
    if (m) { const x = (m.getAttribute('content') || '').match(/url=(.+)$/i); if (x) metaRefresh = x[1].trim().replace(/^['"]|['"]$/g, ''); }
    return { pw: !!document.querySelector('input[type=password]'), forms, links, hiddenIframes, obf, title: document.title || '', metaRefresh };
  }

  function banner(res) {
    if (document.getElementById('siteshield-ai-banner')) return;
    const host = document.createElement('div');
    host.id = 'siteshield-ai-banner';
    const root = host.attachShadow({ mode: 'closed' });
    const bar = document.createElement('div');
    const danger = res.verdict === 'dangerous';
    bar.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;padding:10px 16px;display:flex;gap:12px;align-items:center;font:14px system-ui,Arial,sans-serif;color:#fff;background:' + (danger ? '#b3261e' : '#8a5a00');
    const msg = document.createElement('span');
    msg.style.flex = '1';
    msg.textContent = (danger ? 'SiteShield AI: this site looks dangerous. ' : 'SiteShield AI: this site looks suspicious. ') + (res.reasons[0] || '') + ' Do not enter passwords or payment details.';
    const mk = (t, fn) => { const b = document.createElement('button'); b.textContent = t; b.style.cssText = 'cursor:pointer;border:1px solid #fff;background:transparent;color:#fff;border-radius:6px;padding:4px 10px;font:inherit'; b.onclick = fn; return b; };
    bar.append(msg,
      mk('Trust this site', () => { chrome.runtime.sendMessage({ type: 'trust', domain: res.rd }); host.remove(); }),
      mk('Dismiss', () => host.remove()));
    root.append(bar);
    document.documentElement.append(host);
  }

  const send = () => chrome.runtime.sendMessage({ type: 'page', data: collect() }, (res) => {
    if (chrome.runtime.lastError || !res) return;
    if (res.verdict === 'dangerous' || res.verdict === 'suspicious') banner(res);
  });
  send();
  setTimeout(send, 3000);
})();
