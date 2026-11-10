const $ = (id) => document.getElementById(id);
const COLOR = { dangerous: '#d93025', suspicious: '#f9ab00', safe: '#188038', trusted: '#188038', internal: '#5f6368', unknown: '#5f6368' };
const TITLE = { dangerous: 'Dangerous site', suspicious: 'Suspicious site', safe: 'Looks safe', trusted: 'Trusted by you', internal: 'Not scanned', unknown: 'Unknown page' };
let current = null, tabInfo = null;

function render(res, note) {
  current = res;
  $('note').textContent = note || '';
  $('title').textContent = TITLE[res.verdict] || 'Unknown';
  $('host').textContent = res.host || res.url || '';
  $('dot').style.background = COLOR[res.verdict];
  $('fill').style.background = COLOR[res.verdict];
  $('fill').style.width = Math.round((res.risk || 0) * 100) + '%';
  $('riskline').textContent = res.verdict === 'internal' || res.verdict === 'unknown' ? '' : 'Risk score: ' + Math.round((res.risk || 0) * 100) + '%' + (res.scanned ? ' (URL and page content)' : ' (URL only)');
  const ul = $('reasons');
  ul.textContent = '';
  (res.reasons || []).forEach((r) => { const li = document.createElement('li'); li.textContent = r; ul.append(li); });
  const t = $('trust');
  if (res.rd && note !== 'Checked URL') { t.hidden = false; t.textContent = res.verdict === 'trusted' ? 'Remove trust' : 'Trust this site'; } else t.hidden = true;
}

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  tabInfo = { tabId: tab.id, url: tab.url || '' };
  chrome.runtime.sendMessage({ type: 'get', tabId: tab.id, url: tab.url }, (res) => res && render(res));
}
$('trust').onclick = () => {
  if (!current || !current.rd || !tabInfo) return;
  chrome.runtime.sendMessage({ type: current.verdict === 'trusted' ? 'untrust' : 'trust', domain: current.rd }, () =>
    chrome.runtime.sendMessage({ type: 'rescan', ...tabInfo }, (res) => res && render(res)));
};
$('go').onclick = () => {
  let v = $('u').value.trim();
  if (!v) return;
  if (!/^[a-z][a-z0-9+.-]*:/i.test(v)) v = 'http://' + v;
  chrome.runtime.sendMessage({ type: 'check', url: v }, (res) => res && render(res, 'Checked URL'));
};
$('u').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('go').click(); });
init();
