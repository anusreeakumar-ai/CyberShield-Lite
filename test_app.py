"""Quick checks for the main workflows. Run with:  python test_app.py
Uses a temporary database, so your real database.db is not touched."""
import io
import os
import tempfile

os.environ["CYBERSHIELD_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

import app as cybershield  # noqa: E402

client = cybershield.app.test_client()
passed = 0


def check(name, condition):
    global passed
    assert condition, "FAILED: " + name
    passed += 1
    print("ok  -", name)


def upload(path, content, name="report.txt", **extra):
    data = {"file": (io.BytesIO(content), name), **extra}
    return client.post(path, data=data, content_type="multipart/form-data")


# --- pages ---
check("dashboard loads", client.get("/").status_code == 200)
check("tools page loads", client.get("/tools").status_code == 200)

# --- URL detector ---
r = client.post("/api/scan-url", json={"url": "http://signin-secure-account.example.com/verify?id=1"})
j = r.get_json()
check("risky URL scores high", r.status_code == 200 and j["risk_level"] == "High" and j["risk_score"] >= 70)
check("risky URL has reasons", any(x["level"] == "warn" for x in j["reasons"]))
r = client.post("/api/scan-url", json={"url": "https://www.example.com/about"})
check("normal URL scores low", r.get_json()["risk_level"] == "Low")
r = client.post("/api/scan-url", json={"url": "www.example.com"})
check("scheme-less URL accepted with note", r.status_code == 200 and r.get_json()["reasons"][0]["level"] == "info")
for bad in ["", "   ", "javascript:alert(1)", "http://", "http://bad host.com", "http://nodots", "ftp://example.com", "a" * 2500]:
    check("rejects invalid URL %r" % bad[:20], client.post("/api/scan-url", json={"url": bad}).status_code == 400)
check("rejects non-JSON body", client.post("/api/scan-url", data="x").status_code == 400)
check("scan history saved", len(client.get("/api/scans").get_json()["scans"]) == 3)

# --- file integrity ---
r = upload("/api/files/verify", b"hello")
check("verify without baseline -> 404", r.status_code == 404)
r = upload("/api/files/register", b"hello")
check("register baseline", r.status_code == 200 and r.get_json()["outcome"] == "registered")
check("sha256 correct", r.get_json()["sha256"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
r = upload("/api/files/register", b"other")
check("duplicate baseline needs explicit replace", r.status_code == 409)
r = upload("/api/files/verify", b"hello")
check("same file -> Unchanged", r.get_json()["status"] == "Unchanged")
r = upload("/api/files/verify", b"hello!")
check("changed file -> Modified", r.get_json()["status"] == "Modified")
r = upload("/api/files/register", b"hello!", replace="true")
check("explicit replace works", r.get_json()["outcome"] == "replaced")
r = upload("/api/files/verify", b"hello!")
check("verify against new baseline -> Unchanged", r.get_json()["status"] == "Unchanged")
check("empty file rejected", upload("/api/files/register", b"", name="empty.txt").status_code == 400)
check("missing file rejected", client.post("/api/files/verify", data={}).status_code == 400)
r = upload("/api/files/verify", b"x", name="../../etc/passwd")
check("path in filename is stripped", r.get_json()["error"].count("passwd") == 1 and "/etc" not in r.get_json()["error"])
checks = client.get("/api/files/checks").get_json()
check("check history saved", len(checks["checks"]) == 3 and checks["baseline_count"] == 1)

# --- content-based comparison, independent of file name ---
r = upload("/api/files/verify", b"hello!", name="renamed.txt")
check("renamed file without choosing baseline -> 404", r.status_code == 404)
r = upload("/api/files/verify", b"hello!", name="renamed.txt", baseline="report.txt")
check("renamed file, same content -> Unchanged", r.get_json()["status"] == "Unchanged")
r = upload("/api/files/verify", b"hello! edited", name="renamed.txt", baseline="report.txt")
check("renamed file, changed content -> Modified", r.get_json()["status"] == "Modified")
r = upload("/api/files/verify", b"hello!", name="x.txt", baseline="missing.txt")
check("unknown chosen baseline -> 404", r.status_code == 404)
check("baseline list endpoint", [b["filename"] for b in client.get("/api/files/baselines").get_json()["baselines"]] == ["report.txt"])

# --- dashboard reflects real counts ---
html = client.get("/").get_data(as_text=True)
check("dashboard shows activity", "Verified report.txt: modified" in html)
s = cybershield.collect_stats(__import__("sqlite3").connect(cybershield.DB_PATH))
print("stats:", s)
print("\nAll %d checks passed." % passed)
