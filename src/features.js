export const URL_FEATURES = ['url_len','sub_depth','is_ip','has_at','host_hyphens','digit_ratio','punycode','bad_tld','kw_count','no_https','shortener','host_entropy','brand_mismatch','path_depth','n_params','odd_port','dslash'];

const BAD_TLDS = new Set(['tk','top','xyz','click','gq','ml','cf','ga','work','zip','mov','country','kim','loan','men','download','review','stream','racing','win','bid','date','party','cyou','icu','buzz','rest','monster']);
const SHORTENERS = new Set(['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','cutt.ly','rebrand.ly','shorturl.at','tiny.cc']);
const KEYWORDS = ['login','signin','sign-in','verify','verification','secure','account','update','confirm','banking','password','wallet','suspend','unlock','billing','invoice','recover','validate','authenticate'];
const BRANDS = ['paypal','google','facebook','microsoft','apple','amazon','netflix','instagram','whatsapp','linkedin','twitter','dropbox','github','steam','binance','coinbase','metamask','dhl','fedex','usps','bkash','nagad','chase','wellsfargo','citibank','hsbc','outlook','office365'];
const LEGIT = new Set(['microsoftonline.com','office.com','office365.com','live.com','outlook.com','gmail.com','googleapis.com','gstatic.com','googleusercontent.com','youtube.com','fb.com','amazonaws.com','githubusercontent.com','cloudfront.net']);
const TRUSTED = new Set(['google.com','youtube.com','github.com','microsoft.com','microsoftonline.com','live.com','office.com','apple.com','amazon.com','facebook.com','instagram.com','wikipedia.org','linkedin.com','twitter.com','x.com','reddit.com','stackoverflow.com','cloudflare.com','claude.ai','anthropic.com','openai.com','mozilla.org','paypal.com']);
const SLD2 = new Set(['co','com','org','net','gov','edu','ac','or','ne']);
const AFFIX = /^(\d+|secure|login|support|verify|account|update|online|help|service|pay|mail|id|app|web|care|my|get)$/;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

export const LABELS = {
  url_len: 'Unusually long URL', sub_depth: 'Many nested subdomains', is_ip: 'Uses a raw IP address instead of a domain',
  has_at: 'URL contains an @ to hide the real destination', host_hyphens: 'Many hyphens in the domain name',
  digit_ratio: 'Domain name is full of digits', punycode: 'Look-alike (punycode) characters in the domain',
  bad_tld: 'Domain ending often abused by attackers', kw_count: 'Sensitive words like login, verify or account in the URL',
  no_https: 'Connection is not encrypted (no HTTPS)', shortener: 'Shortened link hides the real destination',
  host_entropy: 'Domain name looks random', brand_mismatch: 'Imitates a well-known brand on an unrelated domain',
  path_depth: 'Very deep URL path', n_params: 'Many URL parameters', odd_port: 'Uses an unusual port', dslash: 'Double slash in path (possible redirect trick)',
  pw_on_http: 'Asks for a password on an unencrypted page', ext_form: 'Form sends your data to a different website',
  empty_pw_form: 'Password form with no clear destination', hidden_iframes: 'Hidden frames embedded in the page',
  ext_link_ratio: 'Most links point to other websites', mismatch_links: 'Link text shows one site but goes to another',
  obf_scripts: 'Obfuscated or encoded scripts', title_brand: 'Page title uses a brand name that does not match the domain',
  meta_refresh_ext: 'Page automatically redirects to another site'
};

const clip = (x, lo = 0, hi = 1) => Math.max(lo, Math.min(hi, x));
export const hostOf = (u) => u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
export function isIp(h) { return IPV4.test(h) || h.includes(':') || /^0x[0-9a-f]+$/.test(h) || /^\d+$/.test(h); }
export function regDomain(h) {
  if (isIp(h)) return h;
  const p = h.split('.');
  if (p.length <= 2) return h;
  if (p[p.length - 1].length === 2 && SLD2.has(p[p.length - 2])) return p.slice(-3).join('.');
  return p.slice(-2).join('.');
}
function entropy(s) {
  if (!s) return 0;
  const c = {};
  for (const ch of s) c[ch] = (c[ch] || 0) + 1;
  let h = 0;
  for (const k in c) { const p = c[k] / s.length; h -= p * Math.log2(p); }
  return h;
}
function brandInHost(host, rd) {
  if (LEGIT.has(rd)) return null;
  const sld = rd.split('.')[0];
  for (const tok of host.split(/[.\-_]/)) {
    for (const b of BRANDS) {
      let hit = tok === b;
      if (!hit && tok.startsWith(b) && AFFIX.test(tok.slice(b.length))) hit = true;
      if (!hit && tok.endsWith(b) && AFFIX.test(tok.slice(0, tok.length - b.length))) hit = true;
      if (hit && sld !== b) return b;
    }
  }
  return null;
}

export function urlFeatures(raw) {
  let u;
  try { u = new URL(raw); } catch (e) { return null; }
  const host = hostOf(u), ip = isIp(host), rd = regDomain(host);
  const labels = host.split('.');
  const rdN = rd.split('.').length;
  let sub = ip ? [] : labels.slice(0, Math.max(0, labels.length - rdN));
  if (sub.length && sub[0] === 'www') sub = sub.slice(1);
  const s = (host + u.pathname + u.search).toLowerCase();
  const kw = KEYWORDS.filter((k) => s.includes(k)).length;
  const brand = ip ? null : brandInHost(host, rd);
  const segs = u.pathname.split('/').filter(Boolean).length;
  const params = u.search.slice(1).split('&').filter(Boolean).length;
  const digits = (host.match(/\d/g) || []).length;
  const f = {
    url_len: clip(raw.replace(/\/+$/, '').length / 200),
    sub_depth: clip(sub.length / 4),
    is_ip: ip ? 1 : 0,
    has_at: (u.username || u.password) ? 1 : 0,
    host_hyphens: clip((host.split('-').length - 1) / 4),
    digit_ratio: ip ? 0 : digits / Math.max(host.length, 1),
    punycode: host.includes('xn--') ? 1 : 0,
    bad_tld: !ip && BAD_TLDS.has(labels[labels.length - 1]) ? 1 : 0,
    kw_count: clip(kw / 3),
    no_https: u.protocol !== 'https:' ? 1 : 0,
    shortener: SHORTENERS.has(rd) ? 1 : 0,
    host_entropy: ip ? 0 : clip((entropy(rd.split('.')[0]) - 2.5) / 1.5),
    brand_mismatch: brand ? 1 : 0,
    path_depth: clip(segs / 8),
    n_params: clip(params / 8),
    odd_port: u.port && u.port !== '80' && u.port !== '443' ? 1 : 0,
    dslash: u.pathname.includes('//') ? 1 : 0
  };
  return { f, meta: { host, rd, brand } };
}

export function pageFeatures(pg, raw) {
  const u = new URL(raw), rd = regDomain(hostOf(u));
  const abs = (h) => { try { return new URL(h, u); } catch (e) { return null; } };
  const ext = (h) => { const a = abs(h); return !!a && /^https?:$/.test(a.protocol) && regDomain(hostOf(a)) !== rd; };
  const forms = pg.forms || [], links = pg.links || [];
  let mism = 0;
  for (const l of links) {
    const t = (l.text || '').trim();
    if (!t || t.length > 80 || !/^(https?:\/\/|www\.)?([a-z0-9-]+\.)+[a-z]{2,}(\/\S*)?$/i.test(t)) continue;
    const a = abs(l.href), b = abs(/^https?:/i.test(t) ? t : 'http://' + t);
    if (a && b && /^https?:$/.test(a.protocol) && regDomain(hostOf(a)) !== regDomain(hostOf(b))) mism++;
  }
  let titleBrand = 0;
  if (pg.pw) {
    const words = (pg.title || '').toLowerCase().split(/[^a-z0-9]+/);
    const b = BRANDS.find((x) => words.includes(x));
    if (b && rd.split('.')[0] !== b && !LEGIT.has(rd)) titleBrand = 1;
  }
  return {
    pw_on_http: pg.pw && u.protocol !== 'https:' ? 1 : 0,
    ext_form: forms.some((x) => (x.pw || x.method === 'post') && ext(x.action)) ? 1 : 0,
    empty_pw_form: forms.some((x) => x.pw && (!x.action || x.action === '#' || /^(javascript:|about:blank)/i.test(x.action))) ? 1 : 0,
    hidden_iframes: clip((pg.hiddenIframes || 0) / 3),
    ext_link_ratio: links.length >= 5 ? links.filter((l) => ext(l.href)).length / links.length : 0,
    mismatch_links: clip(mism / 3),
    obf_scripts: clip((pg.obf || 0) / 5),
    title_brand: titleBrand,
    meta_refresh_ext: pg.metaRefresh && ext(pg.metaRefresh) ? 1 : 0
  };
}

const PRIVATE = /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/;
export function analyze(raw, page, model, allow = []) {
  let u;
  try { u = new URL(raw); } catch (e) { return { url: raw, verdict: 'unknown', risk: 0, reasons: [] }; }
  if (!/^https?:$/.test(u.protocol)) return { url: raw, verdict: 'internal', risk: 0, reasons: ['Browser or local page, not scanned'] };
  const h = hostOf(u);
  if (h === 'localhost' || h.endsWith('.local') || (isIp(h) && PRIVATE.test(h))) return { url: raw, host: h, verdict: 'internal', risk: 0, reasons: ['Local network address, not scanned'] };
  const { f, meta } = urlFeatures(raw);
  if (page) Object.assign(f, pageFeatures(page, raw));
  const base = { url: raw, host: meta.host, rd: meta.rd, scanned: !!page };
  if (allow.includes(meta.rd)) return { ...base, verdict: 'trusted', risk: 0, reasons: ['You marked this site as trusted'] };
  let z = model.bias;
  const contrib = [];
  for (const k in f) {
    const c = (model.weights[k] || 0) * f[k];
    z += c;
    if (c >= 0.5) contrib.push([k, c]);
  }
  let p = 1 / (1 + Math.exp(-z));
  contrib.sort((a, b) => b[1] - a[1]);
  let reasons = contrib.slice(0, 5).map(([k]) => (k === 'brand_mismatch' ? 'Imitates "' + meta.brand + '" on an unrelated domain' : LABELS[k]));
  if (TRUSTED.has(meta.rd)) { p = Math.min(p, 0.02); reasons = ['Well-known trusted domain']; }
  const t = model.thresholds;
  const verdict = p >= t.dangerous ? 'dangerous' : p >= t.suspicious ? 'suspicious' : 'safe';
  if (verdict === 'safe' && !reasons.length) reasons = ['No common phishing indicators found'];
  return { ...base, verdict, risk: Math.round(p * 1000) / 1000, reasons };
}
