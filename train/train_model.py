"""Train the URL part of the SiteShield AI model.

Usage:
  pip install scikit-learn pandas
  python train/train_model.py --csv data/urls.csv --out src/model.json

CSV columns: url,label   (label 1 = malicious/phishing, 0 = benign)
Suggested sources: PhishTank or OpenPhish (malicious) + Tranco top sites (benign), or a public
"malicious URLs" dataset from Kaggle/UCI. Balance the classes and remove duplicates.
Page-content weights are kept from the existing model.json (URL datasets have no page data).
"""
import argparse, json
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from features_py import URL_FEATURES, url_features

ap = argparse.ArgumentParser()
ap.add_argument('--csv', required=True)
ap.add_argument('--out', default='src/model.json')
ap.add_argument('--C', type=float, default=1.0)
a = ap.parse_args()

df = pd.read_csv(a.csv).dropna(subset=['url', 'label']).drop_duplicates('url')
X = [[url_features(u)[k] for k in URL_FEATURES] for u in df['url']]
y = df['label'].astype(int).tolist()
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

clf = LogisticRegression(C=a.C, class_weight='balanced', max_iter=2000).fit(Xtr, ytr)
prob = clf.predict_proba(Xte)[:, 1]
print(classification_report(yte, (prob >= 0.5).astype(int), target_names=['benign', 'malicious']))
print('ROC AUC:', round(roc_auc_score(yte, prob), 4))

model = json.load(open(a.out))
model['bias'] = float(clf.intercept_[0])
for k, w in zip(URL_FEATURES, clf.coef_[0]): model['weights'][k] = float(w)
model['trained'] = True
model['version'] = 'trained-' + str(len(df)) + '-urls'
model['note'] = 'URL weights trained with train/train_model.py; page weights are hand-set.'
json.dump(model, open(a.out, 'w'), indent=2)
print('Saved', a.out)
