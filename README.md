# CyberShield Lite

Phishing URL detection and file integrity checking in a small Flask app.
Two pages only: **Dashboard** (`/`) and **Security Tools** (`/tools`).

## Run it (Windows PowerShell)

Requires Python 3.9 or newer.

```powershell
cd cybershield-lite
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Then open <http://127.0.0.1:5000> in your browser. Press `Ctrl+C` in PowerShell to stop.

If PowerShell blocks the activation script, run this once and try again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

To run the built-in checks (uses a temporary database):

```powershell
python test_app.py
```

## What happens on the first run

The app creates everything it needs automatically:

- `database.db` - SQLite file with scan history, file baselines, check results and activity.
- `data/synthetic_urls.csv` - about 1,000 generated URL records.
- `data/phishing_model.joblib` and `data/model_meta.json` - the trained model and its stats.

Delete the `data/` folder to regenerate the dataset and retrain. Delete `database.db` to clear all history.

## Security Tools

**Phishing URL Detector.** Enter a URL. The app extracts features (length, dots, hyphens in the domain,
HTTPS, IP address, suspicious keywords, "@", digits, subdomains, path depth, query parameters),
scores it with a scikit-learn logistic regression model, and shows a risk score, a risk level
(Low under 40, Medium 40-69, High 70 and above) and the reasons behind it. Every scan is saved in SQLite.

**File Integrity Checker.** Upload a file and choose *Register baseline* to store its SHA-256 hash.
Upload it again later and choose *Verify integrity* to see **Unchanged** or **Modified**.
If a baseline already exists for that file name, tick *Replace existing baseline* to overwrite it.
The hash is calculated from the file's content only, never its name, so any change to the content gives a different hash.
Verification looks for a baseline with the same file name by default. To check a renamed file, pick its baseline in the *Compare against* list.

## Important limits

- **Predictions are educational estimates.** The model is trained on a small synthetic dataset built from
  reserved example domains (`example.com`, `example.org`, `example.net`) and documentation IP ranges.
  A score is not proof that a real website is safe or malicious. Do not use it for real security decisions.
- **URLs are never opened.** They are analysed as text only. The app makes no network requests.
- **Uploaded files are private.** They are hashed in memory in chunks, never written to disk and never executed.
  Only the file name, hashes, size and timestamps are stored. Upload limit: 50 MB.
- **Synthetic vs. real.** The dashboard labels the model's training data as synthetic. Counts, activity and
  file check results come only from what you actually scan or verify.
- A matching hash shows a file is identical to the baseline you registered. It does not show the baseline itself was safe.

## Project layout

```
cybershield-lite/
  app.py            Flask routes, validation, SQLite
  model.py          feature extraction, synthetic data, training, prediction
  requirements.txt
  test_app.py       workflow checks
  templates/        base.html, dashboard.html, tools.html
  static/           style.css, script.js
  README.md
```
