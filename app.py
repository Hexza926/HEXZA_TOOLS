from flask import Flask, request, jsonify, render_template, send_file
from io import BytesIO, StringIO
import csv, ipaddress, os, re, time
import requests
from datetime import datetime, timezone

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

# Webhook URLs are held in server memory only. They are never returned to the browser.
WEBHOOKS = {"cookie": None, "nontrue": None, "bypass": None}
ADMIN_KEY = os.environ.get("HEXZA_ADMIN_KEY", "")

TOOL_NAMES = {
    "cookie": "Cookie Security Checker",
    "nontrue": "Nontrue Checker",
    "bypass": "Bypass Diagnostics"
}

def authorized():
    supplied = request.headers.get("X-Admin-Key", "")
    return bool(ADMIN_KEY) and supplied == ADMIN_KEY

def safe_text(value, limit=180):
    value = str(value or "").strip()
    value = re.sub(r"[\x00-\x1f\x7f]", "", value)
    return value[:limit] or "Not provided"

def validate_webhook(url):
    # Only accept standard Discord webhook endpoints.
    return bool(re.fullmatch(
        r"https://(discord\.com|discordapp\.com)/api/webhooks/\d+/[A-Za-z0-9._-]+",
        url or ""
    ))

def send_embed(tool, title, description, fields, color=5793266):
    url = WEBHOOKS.get(tool)
    if not url:
        return False, "Webhook not configured"
    payload = {
        "username": "HEXZA TOOLS",
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": title[:256],
            "description": description[:4000],
            "color": color,
            "fields": fields[:25],
            "footer": {"text": "HEXZA TOOLS • Diagnostics only"},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }]
    }
    try:
        response = requests.post(url, json=payload, timeout=15)
        return response.status_code in (200, 204), f"Discord HTTP {response.status_code}"
    except requests.RequestException:
        app.logger.exception("Discord webhook request failed")
        return False, "Webhook delivery failed"

def send_txt(tool, filename, content, title, description):
    url = WEBHOOKS.get(tool)
    if not url:
        return False, "Webhook not configured"
    payload = {
        "username": "HEXZA TOOLS",
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": title,
            "description": description,
            "color": 5793266,
            "footer": {"text": "HEXZA TOOLS • Safe report"},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }]
    }
    try:
        files = {"file": (filename, content.encode("utf-8"), "text/plain")}
        response = requests.post(
            url,
            data={"payload_json": __import__("json").dumps(payload)},
            files=files,
            timeout=20
        )
        return response.status_code in (200, 204), f"Discord HTTP {response.status_code}"
    except requests.RequestException:
        app.logger.exception("Discord TXT upload failed")
        return False, "TXT upload failed"

def country_for_ip(raw_ip):
    try:
        ip = ipaddress.ip_address(raw_ip)
    except ValueError:
        return "INVALID IP", "IP address format is invalid"
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return "PRIVATE / RESERVED", "Public country lookup is not applicable"
    # The submitted public IP is sent to ipapi.co for country lookup.
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=8)
        if r.ok:
            data = r.json()
            return safe_text(data.get("country_name"), 80), safe_text(data.get("country_code"), 20)
    except (requests.RequestException, ValueError):
        pass
    return "LOOKUP UNAVAILABLE", "Could not retrieve country"

def validate_record(row):
    username = safe_text(row.get("username"), 20)
    user_id = safe_text(row.get("user_id"), 24)
    ip_raw = safe_text(row.get("ip_address"), 64)
    profile = safe_text(row.get("profile_url"), 240)

    errors = []
    if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username):
        errors.append("Username format invalid")
    if not user_id.isdigit():
        errors.append("User ID must contain digits")
    profile_match = re.fullmatch(
        r"https://www\.roblox\.com/users/(\d+)/profile/?",
        profile
    )
    if not profile_match:
        errors.append("Roblox profile URL format invalid")
    elif user_id.isdigit() and profile_match.group(1) != user_id:
        errors.append("Profile URL ID does not match User ID")

    country, country_code = country_for_ip(ip_raw)
    try:
        ipaddress.ip_address(ip_raw)
        ip_valid = True
    except ValueError:
        ip_valid = False
        errors.append("IP address format invalid")

    return {
        "username": username,
        "user_id": user_id,
        "ip_address": ip_raw,
        "country": country,
        "country_code": country_code,
        "profile_url": profile,
        "status": "VALID FORMAT" if not errors else "INVALID FORMAT",
        "errors": errors
    }

def report_text(records):
    lines = [
        "HEXZA TOOLS - NONTRUE DIAGNOSTICS REPORT",
        "Generated: " + datetime.now().astimezone().isoformat(),
        "Note: This report checks data format only. It does not test credentials or account ownership.",
        "Passwords, cookies, session tokens and recovery codes are not collected or exported.",
        ""
    ]
    valid = sum(1 for x in records if x["status"] == "VALID FORMAT")
    invalid = len(records) - valid
    lines += [f"TOTAL: {len(records)}", f"VALID FORMAT: {valid}", f"INVALID FORMAT: {invalid}", ""]
    for i, x in enumerate(records, 1):
        lines += [
            f"--- RECORD {i} ---",
            f"Username: {x['username']}",
            f"Password: [REDACTED / NOT COLLECTED]",
            f"User ID: {x['user_id']}",
            f"IP Address: {x['ip_address']}",
            f"IP Country: {x['country']} ({x['country_code']})",
            f"Profile URL: {x['profile_url']}",
            f"Status: {x['status']}",
            f"Details: {'; '.join(x['errors']) if x['errors'] else 'No format errors'}",
            ""
        ]
    return "\n".join(lines), valid, invalid

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/api/webhook/<tool>")
def configure_webhook(tool):
    if tool not in WEBHOOKS:
        return jsonify(error="Unknown tool"), 404
    if not authorized():
        return jsonify(error="Admin key is missing or incorrect"), 401
    url = (request.json or {}).get("url", "").strip()
    if not validate_webhook(url):
        return jsonify(error="Discord webhook URL format is invalid"), 400
    WEBHOOKS[tool] = url
    return jsonify(success=True, message="Webhook saved in server memory. It resets when the server restarts.")

@app.post("/api/nontrue")
def nontrue_single():
    if not WEBHOOKS["nontrue"]:
        return jsonify(error="Configure the Nontrue webhook first"), 400
    data = request.get_json(silent=True) or {}
    record = validate_record(data)
    fields = [
        {"name": "Username", "value": record["username"], "inline": True},
        {"name": "Password", "value": "[REDACTED / NOT COLLECTED]", "inline": True},
        {"name": "User ID", "value": record["user_id"], "inline": True},
        {"name": "IP Address", "value": record["ip_address"], "inline": True},
        {"name": "IP Country", "value": f'{record["country"]} ({record["country_code"]})', "inline": True},
        {"name": "Profile URL", "value": record["profile_url"][:1024], "inline": False},
        {"name": "Format Check", "value": record["status"], "inline": True},
        {"name": "Details", "value": "; ".join(record["errors"])[:1024] or "No format errors", "inline": False}
    ]
    ok, msg = send_embed("nontrue", "🔎 NONTRUE CHECK RESULT", "Data format diagnostics completed.", fields,
                         0x2ECC71 if record["status"] == "VALID FORMAT" else 0xE74C3C)
    return jsonify(success=ok, record=record, delivery=msg), (200 if ok else 502)

@app.post("/api/nontrue/bulk")
def nontrue_bulk():
    if not WEBHOOKS["nontrue"]:
        return jsonify(error="Configure the Nontrue webhook first"), 400
    upload = request.files.get("file")
    if not upload or not upload.filename.lower().endswith((".txt", ".csv")):
        return jsonify(error="Upload a TXT or CSV file"), 400
    raw = upload.read().decode("utf-8-sig", errors="replace")
    if len(raw) > 1_500_000:
        return jsonify(error="File is too large"), 413
    reader = csv.DictReader(StringIO(raw))
    required = {"username", "user_id", "ip_address", "profile_url"}
    if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
        return jsonify(error="Required CSV headers: username,user_id,ip_address,profile_url"), 400
    records = []
    for row in reader:
        if len(records) >= 100:
            break
        records.append(validate_record(row))
    if not records:
        return jsonify(error="No records found"), 400

    # Send one embed per record, sequentially to avoid webhook bursts.
    sent = 0
    for record in records:
        fields = [
            {"name": "Username", "value": record["username"], "inline": True},
            {"name": "Password", "value": "[REDACTED / NOT COLLECTED]", "inline": True},
            {"name": "User ID", "value": record["user_id"], "inline": True},
            {"name": "IP Address", "value": record["ip_address"], "inline": True},
            {"name": "IP Country", "value": f'{record["country"]} ({record["country_code"]})', "inline": True},
            {"name": "Profile URL", "value": record["profile_url"][:1024], "inline": False},
            {"name": "Status", "value": record["status"], "inline": True},
            {"name": "Details", "value": "; ".join(record["errors"])[:1024] or "No format errors", "inline": False}
        ]
        ok, _ = send_embed("nontrue", "🔎 NONTRUE CHECK RESULT",
                           "One record processed. Format checks only.", fields,
                           0x2ECC71 if record["status"] == "VALID FORMAT" else 0xE74C3C)
        sent += int(ok)
        time.sleep(0.8)

    content, valid, invalid = report_text(records)
    summary_ok, summary_msg = send_txt(
        "nontrue", "HEXZA-NONTRUE-REPORT.txt", content,
        "📊 NONTRUE BULK SUMMARY",
        f"Total: {len(records)} • Valid format: {valid} • Invalid format: {invalid} • Individual embeds delivered: {sent}"
    )
    return jsonify(
        success=True, total=len(records), valid=valid, invalid=invalid,
        embeds_sent=sent, txt_sent=summary_ok, txt_delivery=summary_msg,
        download_url="/api/nontrue/download"
    )

@app.post("/api/cookie")
def cookie_report():
    if not WEBHOOKS["cookie"]:
        return jsonify(error="Configure the Cookie Checker webhook first"), 400
    data = request.get_json(silent=True) or {}
    completed = data.get("completed", 0)
    if type(completed) is not int or not 0 <= completed <= 4:
        return jsonify(error="Invalid checklist count"), 400
    fields = [
        {"name": "Security checklist", "value": f"{completed}/4", "inline": True},
        {"name": "Assessment", "value": "Completed", "inline": True},
        {"name": "Credential handling", "value": "No cookies or secrets collected", "inline": False}
    ]
    ok, msg = send_embed("cookie", "🍪 COOKIE SECURITY CHECK", "Security checklist completed.", fields)
    return jsonify(success=ok, delivery=msg), (200 if ok else 502)

@app.post("/api/bypass")
def bypass_report():
    if not WEBHOOKS["bypass"]:
        return jsonify(error="Configure the Bypass webhook first"), 400
    data = request.get_json(silent=True) or {}
    allowed = {"locked", "password", "email", "security", "compromised"}
    problem = data.get("problem")
    if problem not in allowed:
        return jsonify(error="Invalid diagnostic category"), 400
    fields = [
        {"name": "Problem category", "value": problem.title(), "inline": True},
        {"name": "Result", "value": "Recovery guidance provided", "inline": True},
        {"name": "Action", "value": "Use official Roblox Support and recovery", "inline": False}
    ]
    ok, msg = send_embed("bypass", "🛡️ ACCOUNT RECOVERY DIAGNOSTICS",
                         "This tool provides recovery guidance only; it does not bypass account security.", fields)
    return jsonify(success=ok, delivery=msg), (200 if ok else 502)

@app.get("/api/nontrue/download")
def download_report():
    # This endpoint is intentionally not a permanent report store.
    return jsonify(error="Reports are generated per upload and sent directly to Discord. Use the browser result to download your report."), 404

if __name__ == "__main__":
    # Local-only by default. Use a production WSGI server and HTTPS before public deployment.
    app.run(host="127.0.0.1", port=5000, debug=False)