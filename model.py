"""model.py - URL feature extraction, synthetic dataset, training and prediction.

Everything here is educational. The training data is generated locally from
reserved example domains (example.com/.org/.net) and reserved documentation
IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). No real malicious
site is used, and no URL is ever opened or requested.
"""
import csv
import ipaddress
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATASET_PATH = DATA_DIR / "synthetic_urls.csv"
MODEL_PATH = DATA_DIR / "phishing_model.joblib"
META_PATH = DATA_DIR / "model_meta.json"

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "password", "bank", "wallet", "billing", "suspend", "unlock",
    "authenticate", "recover",
]

FEATURE_NAMES = [
    "url_length", "num_dots", "num_hyphens", "has_https", "has_ip",
    "keyword_count", "has_at", "host_digits", "subdomain_count",
    "path_depth", "query_params",
]

# Risk levels: Low < 40, Medium 40-69, High >= 70
MEDIUM_THRESHOLD = 40
HIGH_THRESHOLD = 70


# --------------------------------------------------------------------------
# Feature extraction
# --------------------------------------------------------------------------
def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def keywords_found(url: str) -> list:
    lowered = url.lower()
    return [k for k in SUSPICIOUS_KEYWORDS if k in lowered]


def extract_features(url: str) -> dict:
    """Turn a URL string into the numeric features used by the model."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    is_ip = _is_ip(host)
    path_segments = [s for s in parts.path.split("/") if s]
    query_params = parse_qsl(parts.query, keep_blank_values=True)
    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": host.count("-"),
        "has_https": int(parts.scheme == "https"),
        "has_ip": int(is_ip),
        "keyword_count": len(keywords_found(url)),
        "has_at": int("@" in url),
        "host_digits": sum(c.isdigit() for c in host),
        "subdomain_count": 0 if is_ip else max(host.count(".") - 1, 0),
        "path_depth": len(path_segments),
        "query_params": len(query_params),
    }


def feature_vector(features: dict) -> list:
    return [features[name] for name in FEATURE_NAMES]


# --------------------------------------------------------------------------
# Synthetic dataset (reserved domains only)
# --------------------------------------------------------------------------
DOMAINS = ["example.com", "example.org", "example.net"]
RESERVED_IPS = ["192.0.2.{}", "198.51.100.{}", "203.0.113.{}"]
LEGIT_SUBS = ["www", "docs", "blog", "shop", "news", "help", "portal", "app"]
LEGIT_WORDS = ["about", "products", "pricing", "contact", "guide", "intro", "team",
               "careers", "events", "gallery", "faq", "press", "story", "download"]
BRANDS = ["mybank", "paywallet", "cloudmail", "shopzone", "streamflix", "officehub"]
PHISH_WORDS = ["login", "signin", "verify", "secure", "account", "update",
               "confirm", "password", "billing", "unlock", "authenticate"]
PHISH_SUBS = ["secure", "login", "mail", "web", "id", "my"]
PHISH_QUERY_KEYS = ["session", "token", "user", "redirect", "id"]


def _digits(rng, n):
    return "".join(rng.choice("0123456789") for _ in range(n))


def _hex(rng, n):
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _legit_url(rng) -> str:
    scheme = "https" if rng.random() < 0.88 else "http"
    if rng.random() < 0.04:  # internal-looking IP host (noise)
        host = rng.choice(RESERVED_IPS).format(rng.randint(1, 254))
    else:
        domain = rng.choice(DOMAINS)
        sub = rng.choice(LEGIT_SUBS + [""] * 3)
        host = f"{sub}.{domain}" if sub else domain
        if rng.random() < 0.08:
            host = f"{rng.choice(LEGIT_SUBS)}.{host}"
        if rng.random() < 0.07:  # harmless hyphenated names exist
            host = f"{rng.choice(LEGIT_WORDS)}-{rng.choice(LEGIT_WORDS)}.{domain}"
    port = ":8080" if rng.random() < 0.03 else ""
    depth = rng.choices([0, 1, 2, 3], [2, 4, 3, 1])[0]
    words = [rng.choice(LEGIT_WORDS) for _ in range(depth)]
    if words and rng.random() < 0.08:  # real sites do have login pages
        words[rng.randrange(len(words))] = rng.choice(["login", "account", "update"])
    path = "/" + "/".join(words) if words else ""
    query = ""
    if rng.random() < 0.25:
        query = rng.choice(["?id=" + _digits(rng, 2), "?page=2&sort=asc",
                            "?q=guide", "?ref=newsletter"])
    return f"{scheme}://{host}{port}{path}{query}"


def _phishing_url(rng) -> str:
    domain = rng.choice(DOMAINS)
    scheme = "https" if rng.random() < 0.3 else "http"
    kind = rng.random()
    stealth = False
    if kind < 0.15:  # raw IP host
        host = rng.choice(RESERVED_IPS).format(rng.randint(1, 254))
    elif kind < 0.27:  # "stealthy": clean host, suspicious path only
        stealth = True
        scheme = "https" if rng.random() < 0.8 else "http"
        host = f"{rng.choice(LEGIT_SUBS)}.{domain}"
    else:  # brand + keywords + hyphens + extra subdomains
        label = "-".join([rng.choice(BRANDS)] + rng.sample(PHISH_WORDS, rng.randint(1, 3)))
        subs = ".".join(rng.choice(PHISH_SUBS) for _ in range(rng.randint(0, 3)))
        host = ".".join(p for p in [subs, label, domain] if p)
    if rng.random() < 0.08:  # "@" trick hides the real destination
        host = f"www.{domain}@" + rng.choice(RESERVED_IPS).format(rng.randint(1, 254))
    n_segments = 1 if stealth else rng.randint(1, 4)
    words = [rng.choice(PHISH_WORDS if (stealth or rng.random() < 0.85) else LEGIT_WORDS)
             for _ in range(n_segments)]
    path = "/" + "/".join(words)
    query = ""
    if not stealth and rng.random() < 0.55:
        keys = rng.sample(PHISH_QUERY_KEYS, rng.randint(1, 4))
        query = "?" + "&".join(f"{k}={_hex(rng, 8)}" for k in keys)
    return f"{scheme}://{host}{path}{query}"


def generate_dataset(n_records: int = 1000, seed: int = 42) -> list:
    """Return [(url, label)] where label 1 = phishing-like, 0 = legitimate-like."""
    rng = random.Random(seed)
    rows = []
    for i in range(n_records):
        label = i % 2
        url = _phishing_url(rng) if label else _legit_url(rng)
        if rng.random() < 0.02:  # a little label noise keeps it realistic
            label = 1 - label
        rows.append((url, label))
    rng.shuffle(rows)
    return rows


# --------------------------------------------------------------------------
# Training / loading
# --------------------------------------------------------------------------
_model = None


def train_model(n_records: int = 1000, seed: int = 42) -> dict:
    """Generate the synthetic dataset, train the classifier and save everything."""
    global _model
    DATA_DIR.mkdir(exist_ok=True)
    rows = generate_dataset(n_records, seed)
    with open(DATASET_PATH, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "label", "source"])
        writer.writerows([(u, lbl, "synthetic") for u, lbl in rows])

    X = [feature_vector(extract_features(u)) for u, _ in rows]
    y = [lbl for _, lbl in rows]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=seed, stratify=y)
    pipeline = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000))
    pipeline.fit(X_train, y_train)
    accuracy = float(pipeline.score(X_test, y_test))
    joblib.dump(pipeline, MODEL_PATH)

    meta = {
        "records": len(rows),
        "phishing_like": int(sum(y)),
        "legitimate_like": int(len(y) - sum(y)),
        "algorithm": "Logistic regression (scikit-learn)",
        "holdout_accuracy": round(accuracy, 3),
        "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "data_source": "Synthetic (reserved example domains)",
    }
    META_PATH.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    _model = pipeline
    return meta


def ensure_model() -> None:
    """Train on first run; reload from disk afterwards."""
    global _model
    if _model is not None:
        return
    if not (MODEL_PATH.exists() and META_PATH.exists() and DATASET_PATH.exists()):
        train_model()
        return
    try:
        _model = joblib.load(MODEL_PATH)
    except Exception:  # e.g. saved with another scikit-learn version
        train_model()


def load_meta() -> dict:
    ensure_model()
    return json.loads(META_PATH.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# Prediction + explanation
# --------------------------------------------------------------------------
def risk_level(score: int) -> str:
    if score >= HIGH_THRESHOLD:
        return "High"
    if score >= MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"


def predict_url(url: str):
    """Return (risk_score 1-99, features dict). The URL is only analysed as text."""
    ensure_model()
    features = extract_features(url)
    probability = float(_model.predict_proba([feature_vector(features)])[0][1])
    score = max(1, min(99, round(probability * 100)))
    return score, features


def explain(url: str, features: dict) -> list:
    """Human-readable reasons. level is 'warn' (trigger) or 'ok' (passed check)."""
    warn, ok = [], []
    f = features
    if f["has_ip"]:
        warn.append("Uses a raw IP address instead of a domain name.")
    else:
        ok.append("Uses a normal domain name, not an IP address.")
    if f["has_at"]:
        warn.append("Contains an '@' symbol, which can hide the real destination.")
    if f["has_https"]:
        ok.append("Uses HTTPS (this alone does not prove a site is safe).")
    else:
        warn.append("Does not use HTTPS.")
    found = keywords_found(url)
    if found:
        warn.append("Contains sensitive-sounding keywords: " + ", ".join(found) + ".")
    else:
        ok.append("No sensitive-sounding keywords found.")
    if f["url_length"] > 75:
        warn.append(f"Long URL ({f['url_length']} characters).")
    else:
        ok.append(f"URL length looks normal ({f['url_length']} characters).")
    if f["num_hyphens"] >= 2:
        warn.append(f"Domain contains {f['num_hyphens']} hyphens.")
    if f["subdomain_count"] >= 3:
        warn.append(f"Many subdomain levels ({f['subdomain_count']}).")
    if f["num_dots"] >= 5:
        warn.append(f"Many dots in the URL ({f['num_dots']}).")
    if f["host_digits"] >= 4 and not f["has_ip"]:
        warn.append("Domain name contains many digits.")
    if f["path_depth"] >= 4:
        warn.append(f"Deep path ({f['path_depth']} folders).")
    if f["query_params"] >= 3:
        warn.append(f"Many query parameters ({f['query_params']}).")
    return ([{"level": "warn", "text": t} for t in warn] +
            [{"level": "ok", "text": t} for t in ok])
