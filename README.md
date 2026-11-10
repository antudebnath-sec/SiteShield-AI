# SiteShield AI

An AI-based browser extension (Chrome, Edge, Brave; Manifest V3) that detects phishing and malicious sites **locally** and explains why a site looks risky. No browsing data leaves the browser.

# Install (developer mode)
1. Unzip this folder.
2. Open `chrome://extensions` (or `edge://extensions`) and turn on **Developer mode**.
3. Click **Load unpacked** and select this folder (the one containing `manifest.json`).
4. Pin the extension. The badge shows *OK* (safe), *?* (suspicious) or *!* (dangerous).

# How it works
1. *URL analysis* (background service worker): 17 features such as raw IP hosts, `@` tricks, punycode look-alikes, risky TLDs, brand names on unrelated domains, long or random domains, missing HTTPS.
2. *Page analysis* (content script): password forms that post to another domain, hidden iframes, links whose text shows one site but go to another, obfuscated scripts, meta-refresh redirects, brand names in the title.
3. *AI model*: a logistic-regression classifier turns the features into a risk score from 0 to 100%. Reasons are the features that pushed the score up, so every verdict is explainable.
4. *Action*: toolbar badge, a warning banner on suspicious pages, and a popup with the score and reasons. You can trust or untrust a site, and check any URL without visiting it.

Thresholds: below 50% safe, 50 to 80% suspicious, 80% and above dangerous (editable in `src/model.json`).

# Important: the shipped model is a baseline
`src/model.json` contains hand-set starting weights, not weights learned from data. To get a real trained model:

```bash
pip install scikit-learn pandas
python train/train_model.py --csv data/urls.csv --out src/model.json
```
Use PhishTank or OpenPhish for malicious URLs and the Tranco top-sites list for benign ones (balanced, de-duplicated). The script prints precision, recall, F1 and ROC AUC on a held-out split, which you can use in your report. Reload the extension afterwards.

# Tests
```bash
node test/run_tests.mjs
node test/dump_features.mjs urls.txt > js.json
python train/features_py.py urls.txt > py.json

# Limitations
- It is a heuristic and ML aid, not a replacement for Google Safe Browsing or antivirus. Expect some false positives and misses.
- Only the URL features are trained; page-content weights stay hand-set.
- A well-built phishing page on a clean-looking domain can score low. Possible upgrades: Safe Browsing or PhishTank lookups, domain age (WHOIS), a larger model, and screenshot or logo comparison.

# Files
`manifest.json` · `background.js` (scoring, badge) · `content.js` (page signals, banner) · `popup.*` (UI) · `src/features.js` (features and scoring) · `src/model.json` (weights) · `train/` (training) · `test/`
