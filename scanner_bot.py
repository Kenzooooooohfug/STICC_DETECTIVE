"""
Telegram file-scanner bot (VirusTotal-powered).

Install:  pip install python-telegram-bot==21.* httpx
Env vars: TELEGRAM_TOKEN (from @BotFather), VT_API_KEY (free key from virustotal.com)
Run:      python scanner_bot.py
"""
import asyncio
import hashlib
import os
import tempfile

import httpx
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, MessageHandler, filters

TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
VT_API_KEY = os.environ["VT_API_KEY"]
VT = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY}
MAX_BYTES = 20 * 1024 * 1024  # Telegram bots can download files up to 20 MB

# Plain-language explanations keyed by the malware "category" VirusTotal reports.
EXPLAIN = {
    "ransomware": ("Encrypts your files and demands money to unlock them. "
                   "Can also destroy backups.", "CRITICAL"),
    "trojan": ("Pretends to be a normal program, then gives an attacker access "
               "or downloads more malware.", "HIGH"),
    "spyware": ("Secretly records activity: keystrokes, screenshots, browsing, "
                "and can steal saved logins and messenger sessions "
                "(including Telegram session data).", "HIGH"),
    "stealer": ("Steals saved passwords, cookies, crypto wallets and app sessions "
                "(Telegram Desktop 'tdata' is a common target).", "CRITICAL"),
    "infostealer": ("Same as a stealer: harvests credentials, cookies and sessions.",
                    "CRITICAL"),
    "backdoor": ("Opens a hidden remote-access channel so an attacker can control "
                 "the device.", "CRITICAL"),
    "rat": ("Remote Access Trojan: attacker can see the screen, files, webcam "
            "and run commands.", "CRITICAL"),
    "worm": ("Spreads by itself to other devices or contacts.", "HIGH"),
    "miner": ("Uses your CPU/GPU to mine crypto. Slows the device, "
              "mostly not data-stealing.", "MEDIUM"),
    "coinminer": ("Uses your CPU/GPU to mine crypto.", "MEDIUM"),
    "adware": ("Shows unwanted ads, may change browser settings.", "LOW"),
    "downloader": ("Small program whose job is to fetch and install other malware.",
                   "HIGH"),
    "dropper": ("Installs other malware hidden inside it.", "HIGH"),
    "keylogger": ("Records everything you type, including passwords.", "HIGH"),
    "rootkit": ("Hides deep in the system and is very hard to remove.", "CRITICAL"),
    "pua": ("Potentially unwanted app: not strictly a virus but unwanted/risky.",
            "LOW"),
}


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


async def vt_lookup(client: httpx.AsyncClient, sha: str):
    r = await client.get(f"{VT}/files/{sha}", headers=HEADERS)
    return r.json() if r.status_code == 200 else None


async def vt_upload_and_wait(client: httpx.AsyncClient, path: str, sha: str):
    with open(path, "rb") as f:
        r = await client.post(f"{VT}/files", headers=HEADERS, files={"file": f})
    r.raise_for_status()
    # Poll until the analysis report is ready (max ~2 minutes).
    for _ in range(12):
        await asyncio.sleep(10)
        report = await vt_lookup(client, sha)
        if report and report["data"]["attributes"].get("last_analysis_results"):
            return report
    return None


def build_report(data: dict) -> str:
    a = data["data"]["attributes"]
    stats = a["last_analysis_stats"]
    bad = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    total = sum(stats.values())

    if bad == 0 and sus == 0:
        return (f"✅ No engine flagged this file (0/{total}).\n"
                "That lowers the risk but is not a guarantee. "
                "Brand-new malware can slip through.")

    cls = a.get("popular_threat_classification", {})
    label = cls.get("suggested_threat_label", "unknown")
    cats = [c["value"] for c in cls.get("popular_threat_category", [])]
    families = [n["value"] for n in cls.get("popular_threat_name", [])]

    lines = [f"🚨 Flagged by {bad} malicious / {sus} suspicious out of {total} engines",
             f"Detected as: {label}"]
    if families:
        lines.append("Family: " + ", ".join(families[:3]))

    worst = "MEDIUM"
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    shown = False
    for c in cats or [label.split(".")[0].lower()]:
        info = EXPLAIN.get(c.lower())
        if info:
            shown = True
            lines.append(f"\n• {c.capitalize()}: {info[0]}")
            if order.index(info[1]) > order.index(worst):
                worst = info[1]
    if not shown:
        lines.append("\nType could not be determined. Treat it as dangerous.")

    lines.append(f"\nDanger level: {worst}")
    lines.append("\nWhat to do: do NOT open it. Delete it. If you already ran it, "
                 "disconnect from the internet, run a full antivirus scan, "
                 "change your passwords from a clean device, and in Telegram go to "
                 "Settings > Devices and terminate unknown sessions.")
    return "\n".join(lines)


async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    if doc.file_size and doc.file_size > MAX_BYTES:
        await update.message.reply_text("File is too big (limit 20 MB).")
        return

    await update.message.reply_text("🔎 Scanning, please wait...")
    tg_file = await context.bot.get_file(doc.file_id)

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "sample.bin")  # never execute or open it
        await tg_file.download_to_drive(path)
        sha = sha256_of(path)

        async with httpx.AsyncClient(timeout=60) as client:
            report = await vt_lookup(client, sha)  # known file? instant result
            if report is None:
                report = await vt_upload_and_wait(client, path, sha)

    if report is None:
        await update.message.reply_text("Scan timed out. Try again in a minute.")
        return

    text = build_report(report)
    text += f"\n\nSHA-256: {sha}\nhttps://www.virustotal.com/gui/file/{sha}"
    await update.message.reply_text(text)


def main():
    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    app.run_polling()


if __name__ == "__main__":
    main()