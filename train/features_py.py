"""Python mirror of urlFeatures() in src/features.js. Keep both in sync (see test/dump_features.mjs)."""
import json, math, re, sys
from urllib.parse import urlsplit

URL_FEATURES = ['url_len','sub_depth','is_ip','has_at','host_hyphens','digit_ratio','punycode','bad_tld','kw_count','no_https','shortener','host_entropy','brand_mismatch','path_depth','n_params','odd_port','dslash']
BAD_TLDS = set('tk top xyz click gq ml cf ga work zip mov country kim loan men download review stream racing win bid date party cyou icu buzz rest monster'.split())
SHORTENERS = set('bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly cutt.ly rebrand.ly shorturl.at tiny.cc'.split())
KEYWORDS = ['login','signin','sign-in','verify','verification','secure','account','update','confirm','banking','password','wallet','suspend','unlock','billing','invoice','recover','validate','authenticate']
BRANDS = 'paypal google facebook microsoft apple amazon netflix instagram whatsapp linkedin twitter dropbox github steam binance coinbase metamask dhl fedex usps bkash nagad chase wellsfargo citibank hsbc outlook office365'.split()
LEGIT = set('microsoftonline.com office.com office365.com live.com outlook.com gmail.com googleapis.com gstatic.com googleusercontent.com youtube.com fb.com amazonaws.com githubusercontent.com cloudfront.net'.split())
SLD2 = set('co com org net gov edu ac or ne'.split())
AFFIX = re.compile(r'^(\d+|secure|login|support|verify|account|update|online|help|service|pay|mail|id|app|web|care|my|get)$')
IPV4 = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

def clip(x, lo=0.0, hi=1.0): return max(lo, min(hi, x))

def is_ip(h):
    return bool(IPV4.match(h)) or ':' in h or bool(re.match(r'^0x[0-9a-f]+$', h)) or bool(re.match(r'^\d+$', h))

def reg_domain(h):
    if is_ip(h): return h
    p = h.split('.')
    if len(p) <= 2: return h
    if len(p[-1]) == 2 and p[-2] in SLD2: return '.'.join(p[-3:])
    return '.'.join(p[-2:])

def entropy(s):
    if not s: return 0.0
    c = {}
    for ch in s: c[ch] = c.get(ch, 0) + 1
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in c.values())

def brand_in_host(host, rd):
    if rd in LEGIT: return None
    sld = rd.split('.')[0]
    for tok in re.split(r'[.\-_]', host):
        for b in BRANDS:
            hit = tok == b
            if not hit and tok.startswith(b) and AFFIX.match(tok[len(b):]): hit = True
            if not hit and tok.endswith(b) and AFFIX.match(tok[:len(tok) - len(b)]): hit = True
            if hit and sld != b: return b
    return None

def url_features(raw):
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', raw): raw = 'http://' + raw
    p = urlsplit(raw)
    host = (p.hostname or '').lower()
    try: host = host.encode('idna').decode()
    except Exception: pass
    ip = is_ip(host); rd = reg_domain(host); labels = host.split('.')
    sub = [] if ip else labels[:max(0, len(labels) - len(rd.split('.')))]
    if sub and sub[0] == 'www': sub = sub[1:]
    s = (host + p.path + ('?' + p.query if p.query else '')).lower()
    kw = sum(1 for k in KEYWORDS if k in s)
    brand = None if ip else brand_in_host(host, rd)
    segs = len([x for x in p.path.split('/') if x])
    params = len([x for x in p.query.split('&') if x])
    try: port = p.port
    except ValueError: port = None
    return {
        'url_len': clip(len(raw.rstrip('/')) / 200),
        'sub_depth': clip(len(sub) / 4),
        'is_ip': 1 if ip else 0,
        'has_at': 1 if '@' in p.netloc else 0,
        'host_hyphens': clip((host.count('-')) / 4),
        'digit_ratio': 0 if ip else sum(c.isdigit() for c in host) / max(len(host), 1),
        'punycode': 1 if 'xn--' in host else 0,
        'bad_tld': 1 if (not ip and labels[-1] in BAD_TLDS) else 0,
        'kw_count': clip(kw / 3),
        'no_https': 1 if p.scheme != 'https' else 0,
        'shortener': 1 if rd in SHORTENERS else 0,
        'host_entropy': 0 if ip else clip((entropy(rd.split('.')[0]) - 2.5) / 1.5),
        'brand_mismatch': 1 if brand else 0,
        'path_depth': clip(segs / 8),
        'n_params': clip(params / 8),
        'odd_port': 1 if (port is not None and port not in (80, 443)) else 0,
        'dslash': 1 if '//' in p.path else 0,
    }

if __name__ == '__main__':
    urls = [l.strip() for l in open(sys.argv[1]) if l.strip()]
    print(json.dumps({u: url_features(u) for u in urls}, indent=1, sort_keys=True))
