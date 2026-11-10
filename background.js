import { analyze } from './src/features.js';

let modelP;
const getModel = () => modelP || (modelP = fetch(chrome.runtime.getURL('src/model.json')).then((r) => r.json()));
const getAllow = async () => (await chrome.storage.local.get('allow')).allow || [];
const run = async (url, page) => analyze(url, page, await getModel(), await getAllow());

const BADGES = { dangerous: ['!', '#d93025'], suspicious: ['?', '#f9ab00'], safe: ['OK', '#188038'], trusted: ['OK', '#188038'] };
function badge(tabId, res) {
  const b = BADGES[res.verdict];
  chrome.action.setBadgeText({ tabId, text: b ? b[0] : '' });
  if (b) chrome.action.setBadgeBackgroundColor({ tabId, color: b[1] });
}
async function save(tabId, res, page) {
  await chrome.storage.session.set({ ['tab' + tabId]: { res, page: page || null } });
  badge(tabId, res);
}
const load = async (tabId) => (await chrome.storage.session.get('tab' + tabId))['tab' + tabId];

chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.status === 'loading' && tab.url) save(tabId, await run(tab.url, null), null);
});
chrome.tabs.onRemoved.addListener((id) => chrome.storage.session.remove('tab' + id));

chrome.runtime.onMessage.addListener((msg, sender, send) => {
  (async () => {
    if (msg.type === 'page' && sender.tab) {
      const res = await run(sender.tab.url, msg.data);
      await save(sender.tab.id, res, msg.data);
      send(res);
    } else if (msg.type === 'get' || msg.type === 'rescan') {
      const s = await load(msg.tabId);
      if (msg.type === 'get' && s) return send(s.res);
      const res = await run(msg.url, s ? s.page : null);
      await save(msg.tabId, res, s ? s.page : null);
      send(res);
    } else if (msg.type === 'check') {
      send(await run(msg.url, null));
    } else if (msg.type === 'trust' || msg.type === 'untrust') {
      let a = await getAllow();
      a = msg.type === 'trust' ? [...new Set([...a, msg.domain])] : a.filter((d) => d !== msg.domain);
      await chrome.storage.local.set({ allow: a });
      send(true);
    }
  })();
  return true;
});
