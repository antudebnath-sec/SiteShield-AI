import { readFileSync } from 'node:fs';
import { analyze } from '../src/features.js';
const model = JSON.parse(readFileSync(new URL('../src/model.json', import.meta.url)));
let fail = 0;
const t = (url, want, page) => {
  const r = analyze(url, page || null, model);
  const ok = want === 'bad' ? r.risk >= 0.5 : r.risk < 0.5;
  if (!ok) fail++;
  console.log((ok ? 'PASS ' : 'FAIL ') + want.padEnd(5) + String(Math.round(r.risk * 100)).padStart(4) + '%  ' + r.verdict.padEnd(10) + url);
};
['https://www.google.com/', 'https://github.com/login', 'https://accounts.google.com/signin/v2', 'https://en.wikipedia.org/wiki/Phishing',
 'https://www.bbc.co.uk/news', 'https://stackoverflow.com/questions/12345/how-to', 'https://login.microsoftonline.com/common/oauth2',
 'https://docs.python.org/3/library/urllib.html', 'https://www.daraz.com.bd/products/?q=phone', 'https://shop.example.com/cart?item=5'].forEach((u) => t(u, 'good'));
['http://paypal-secure-login.verify-account.xyz/signin/update', 'http://192.168.1.5.example.tk/login', 'http://203.0.113.7/paypal/login.php',
 'https://secure-bkash-verify.top/account/confirm', 'http://google.com@evil-site.click/login', 'http://xn--pypal-4ve.com/signin',
 'https://apple-id-locked-support.work/unlock/verify?session=1234567890abcdef', 'http://amazon.account-verify.cf/billing/update'].forEach((u) => t(u, 'bad'));
t('https://fake-shop.example.com/pay', 'bad', { pw: true, forms: [{ action: 'http://collector.evil.top/p.php', method: 'post', pw: true }], links: [], hiddenIframes: 2, obf: 4, title: 'PayPal - Log in' });
console.log(fail ? fail + ' test(s) failed' : 'All tests passed');
process.exit(fail ? 1 : 0);
