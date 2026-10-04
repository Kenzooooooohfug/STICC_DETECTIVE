"""
STICC_DETECTIVE - Telegram file-scanner bot (VirusTotal-powered), English + Khmer.

Install:  pip install python-telegram-bot httpx
Env vars: TELEGRAM_TOKEN (from @BotFather), VT_API_KEY (from virustotal.com)
Run:      python scanner_bot.py
"""
import asyncio
import hashlib
import os
import tempfile
from datetime import datetime, timezone

import httpx
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (ApplicationBuilder, CallbackQueryHandler,
                          CommandHandler, ContextTypes, MessageHandler,
                          PicklePersistence, filters)

TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
VT_API_KEY = os.environ["VT_API_KEY"]
VT = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY}
MAX_BYTES = 20 * 1024 * 1024  # Telegram bots can download files up to 20 MB
TG_LIMIT = 4000               # Telegram max message is 4096 characters
DEFAULT_LANG = "en"

ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
LEVELS = {
    "en": {"LOW": "🟨 LOW", "MEDIUM": "🟧 MEDIUM",
           "HIGH": "🟥 HIGH", "CRITICAL": "⛔ CRITICAL"},
    "km": {"LOW": "🟨 ទាប", "MEDIUM": "🟧 មធ្យម",
           "HIGH": "🟥 ខ្ពស់", "CRITICAL": "⛔ ធ្ងន់ធ្ងរបំផុត"},
}

# ---------------------------------------------------------------------------
# All bot text, in both languages. Edit the Khmer here if you want to improve it.
# ---------------------------------------------------------------------------
S = {
    "en": {
        "choose_lang": "Choose your language / សូមជ្រើសរើសភាសា",
        "lang_set": "✅ Language: English",
        "welcome": (
            "👋 Welcome to STICC_DETECTIVE!\n\n"
            "I scan files for viruses, ransomware, spyware and more. 🕵️\n\n"
            "📎 How to use me:\n"
            "1. Tap the paperclip\n"
            "2. Choose \"File\" (not Photo)\n"
            "3. Send it and wait a few seconds\n\n"
            "You'll get:\n"
            "✅ Whether it's safe or infected\n"
            "🦠 What kind of malware it is and what it does\n"
            "🛡️ What to do if you opened it\n"
            "🌐 IP addresses, domains and behaviour details\n\n"
            "Limits: 20 MB max per file.\n"
            "🔒 Privacy: scanned files are shared with VirusTotal, so don't send "
            "private documents.\n\n"
            "Change language anytime with /language\n\n"
            "Go ahead, send me a file!"),
        "hint": ("📎 Please send the file as a File: tap the paperclip, choose "
                 "File, then pick it. Photos and text can't be scanned."),
        "too_big": "File is too big (limit 20 MB).",
        "scanning": "🔎 Scanning, please wait...",
        "collecting": "🧪 Threat found! Collecting IP, domain and behaviour details...",
        "error": "⚠️ Something went wrong while scanning. Please try again in a minute.",
        "timeout": "Scan timed out. Try again in a minute.",
        "unknown": "unknown",
        "v_clean": "✅ CLEAN\nNo engine flagged this file (0/{total}).",
        "v_danger": "🚨 DANGER: this file is very likely malware!",
        "v_likely": "⚠️ LIKELY MALICIOUS: do not open it.",
        "v_sus": "🤔 SUSPICIOUS: could be a false alarm, but be careful.",
        "flagged_by": "Flagged by {n}/{total} antivirus engines.",
        "clean_note": ("Note: this lowers the risk but is not a guarantee. "
                       "Brand-new malware can slip through."),
        "thanks": "🙏 Scan is done. Thank you for using STICC_DETECTIVE",
        "type_title": "🦠 VIRUS TYPE: {t}",
        "type_unknown": "UNKNOWN",
        "detected_as": "Detected as: {label}",
        "family": "Family: {f}",
        "danger_level": "Danger level: {lvl}",
        "what_title": "💥 WHAT IT IS AND WHAT IT CAN DO TO YOU",
        "no_type": ("The engines flagged this file but did not agree on a type. "
                    "Treat it as dangerous."),
        "advice_title": "🛡️ IF YOU ALREADY OPENED OR CLICKED IT",
        "advice_steps": [
            "Disconnect from Wi-Fi/internet right away.",
            "Don't open it again. Delete it and empty the trash/recycle bin.",
            "Run a full scan with a trusted antivirus (Malwarebytes, Microsoft "
            "Defender, etc.).",
            "From a different, clean device, change passwords for your email, "
            "banking and social accounts, and turn on 2-step verification.",
            "In Telegram: Settings > Devices > end all other sessions, and make "
            "sure 2-step verification is on.",
            "Check your bank and crypto accounts for anything strange.",
            "If the device still acts weird, back up personal files (photos, "
            "documents only) and reset it.",
        ],
        "specific_title": "⚠️ Specific to this type:",
        "prevent_title": "✅ HOW TO PREVENT THIS",
        "prevent_items": [
            "Only download from official sites and app stores.",
            "Be careful with .exe, .apk, .scr, .bat, .js, .lnk files and Office "
            "macros, even if a friend sent them (their account may be hacked).",
            "Never turn on macros in documents from strangers.",
            "Keep your phone/computer and apps updated.",
            "Scan files before you open them (like you just did!).",
            "Use strong, different passwords and 2-step verification.",
        ],
        "file_title": "📄 FILE DETAILS",
        "f_name": "Name", "f_type": "Type", "f_size": "Size",
        "f_first": "First seen online", "f_last": "Last scanned",
        "f_times": "Times submitted",
        "f_votes": "Community votes: 👍 {good} safe / 👎 {bad} malicious",
        "f_tags": "Tags",
        "net_title": "🌐 NETWORK DETAILS (defanged so nothing can be clicked)",
        "net_ips": "📍 IP addresses it contacted:",
        "net_domains": "🔗 Domains it contacted:",
        "net_urls": "🕸️ URLs it contacted:",
        "net_flagged": "flagged by {n}",
        "net_none": ("No network activity was recorded. The file may not have been "
                     "run in a sandbox yet, or it doesn't connect to anything."),
        "beh_title": "🧪 BEHAVIOUR (what it did when run in a sandbox)",
        "beh_tags": "Behaviour tags",
        "beh_mitre": "Attack techniques (MITRE ATT&CK):",
        "beh_cmds": "Commands it ran:",
        "beh_files": "Files it created:",
        "beh_regs": "Registry keys it changed:",
        "beh_none": "No sandbox behaviour report is available for this file yet.",
        "det_title": "🔬 TOP ANTIVIRUS DETECTIONS",
    },
    "km": {
        "choose_lang": "Choose your language / សូមជ្រើសរើសភាសា",
        "lang_set": "✅ ភាសា៖ ខ្មែរ",
        "welcome": (
            "👋 សូមស្វាគមន៍មកកាន់ STICC_DETECTIVE!\n\n"
            "ខ្ញុំស្កេនឯកសារ ដើម្បីរកមេរោគ ransomware spyware និងផ្សេងៗទៀត។ 🕵️\n\n"
            "📎 របៀបប្រើ៖\n"
            "1. ចុចរូប 📎\n"
            "2. ជ្រើសរើស \"File\" (មិនមែន Photo ទេ)\n"
            "3. ផ្ញើ រួចរង់ចាំបន្តិច\n\n"
            "អ្នកនឹងទទួលបាន៖\n"
            "✅ ឯកសារសុវត្ថិភាព ឬមានមេរោគ\n"
            "🦠 ប្រភេទមេរោគ និងអ្វីដែលវាធ្វើ\n"
            "🛡️ អ្វីដែលត្រូវធ្វើ ប្រសិនបើអ្នកបានបើកវា\n"
            "🌐 ព័ត៌មាន IP, domain និងឥរិយាបថ\n\n"
            "កំណត់៖ ឯកសារអតិបរមា 20 MB។\n"
            "🔒 ឯកជនភាព៖ ឯកសារដែលស្កេនត្រូវបានចែករំលែកជាមួយ VirusTotal "
            "ដូច្នេះសូមកុំផ្ញើឯកសារឯកជន។\n\n"
            "ប្តូរភាសាបានគ្រប់ពេលដោយ /language\n\n"
            "សូមផ្ញើឯកសារមកខ្ញុំបាន!"),
        "hint": ("📎 សូមផ្ញើជា File៖ ចុចរូប 📎 ជ្រើសរើស File រួចជ្រើសឯកសារ។ "
                 "រូបថត និងអក្សរមិនអាចស្កេនបានទេ។"),
        "too_big": "ឯកសារធំពេក (កំណត់ត្រឹម 20 MB)។",
        "scanning": "🔎 កំពុងស្កេន សូមរង់ចាំ...",
        "collecting": ("🧪 រកឃើញការគំរាមកំហែង! កំពុងប្រមូលព័ត៌មាន IP, domain "
                       "និងឥរិយាបថ..."),
        "error": "⚠️ មានបញ្ហាក្នុងពេលស្កេន។ សូមព្យាយាមម្តងទៀតក្នុងរយៈពេលមួយនាទី។",
        "timeout": "ការស្កេនអស់ពេល។ សូមព្យាយាមម្តងទៀតក្នុងរយៈពេលមួយនាទី។",
        "unknown": "មិនស្គាល់",
        "v_clean": ("✅ សុវត្ថិភាព\nគ្មានម៉ាស៊ីនស្កេនណាមួយរកឃើញមេរោគក្នុងឯកសារនេះទេ "
                    "(0/{total})។"),
        "v_danger": "🚨 គ្រោះថ្នាក់៖ ឯកសារនេះប្រហែលជាមេរោគ!",
        "v_likely": "⚠️ ទំនងជាមេរោគ៖ សូមកុំបើកវា។",
        "v_sus": "🤔 គួរឱ្យសង្ស័យ៖ អាចជាការព្រមានមិនពិត ប៉ុន្តែសូមប្រយ័ត្ន។",
        "flagged_by": "រកឃើញដោយ {n}/{total} ម៉ាស៊ីនស្កេនមេរោគ។",
        "clean_note": ("ចំណាំ៖ នេះកាត់បន្ថយហានិភ័យ ប៉ុន្តែមិនមែនជាការធានាទេ។ "
                       "មេរោគថ្មីៗអាចរួចផុតពីការរកឃើញ។"),
        "thanks": "🙏 ការស្កេនបានបញ្ចប់។ សូមអរគុណដែលបានប្រើ STICC_DETECTIVE",
        "type_title": "🦠 ប្រភេទមេរោគ៖ {t}",
        "type_unknown": "មិនស្គាល់",
        "detected_as": "ឈ្មោះដែលរកឃើញ៖ {label}",
        "family": "ក្រុមមេរោគ៖ {f}",
        "danger_level": "កម្រិតគ្រោះថ្នាក់៖ {lvl}",
        "what_title": "💥 វាជាអ្វី និងអាចធ្វើអ្វីចំពោះអ្នក",
        "no_type": ("ម៉ាស៊ីនស្កេនបានសម្គាល់ឯកសារនេះ ប៉ុន្តែមិនឯកភាពគ្នាលើប្រភេទទេ។ "
                    "សូមចាត់ទុកថាវាមានគ្រោះថ្នាក់។"),
        "advice_title": "🛡️ ប្រសិនបើអ្នកបានបើក ឬចុចវារួចហើយ",
        "advice_steps": [
            "កាត់ផ្តាច់ Wi-Fi/អ៊ីនធឺណិតភ្លាមៗ។",
            "កុំបើកវាម្តងទៀត។ លុបវា ហើយសម្អាតធុងសំរាម។",
            "ស្កេនឧបករណ៍ទាំងមូលដោយប្រើកម្មវិធីកំចាត់មេរោគដែលអាចទុកចិត្តបាន "
            "(Malwarebytes, Microsoft Defender ។ល។)។",
            "ពីឧបករណ៍ផ្សេងដែលស្អាត សូមប្តូរពាក្យសម្ងាត់អ៊ីមែល ធនាគារ និងបណ្តាញសង្គម "
            "ហើយបើកការផ្ទៀងផ្ទាត់ ២ ជំហាន។",
            "ក្នុង Telegram៖ Settings > Devices > បញ្ចប់ session ផ្សេងទាំងអស់ "
            "ហើយបើកការផ្ទៀងផ្ទាត់ ២ ជំហាន (2-step verification)។",
            "ពិនិត្យគណនីធនាគារ និងគ្រីបតូរបស់អ្នក មើលថាមានអ្វីចម្លែកឬអត់។",
            "បើឧបករណ៍នៅតែដំណើរការចម្លែក សូមបម្រុងទុកឯកសារផ្ទាល់ខ្លួន "
            "(តែរូបថត និងឯកសារ) រួចកំណត់ឧបករណ៍ឡើងវិញ (reset)។",
        ],
        "specific_title": "⚠️ ពិសេសសម្រាប់ប្រភេទនេះ៖",
        "prevent_title": "✅ របៀបការពារ",
        "prevent_items": [
            "ទាញយកតែពីគេហទំព័រផ្លូវការ និង app store ប៉ុណ្ណោះ។",
            "ប្រយ័ត្នជាមួយឯកសារ .exe, .apk, .scr, .bat, .js, .lnk និង macro នៃ Office "
            "ទោះមិត្តភក្តិផ្ញើមកក៏ដោយ (គណនីរបស់គេអាចត្រូវបានលួច)។",
            "កុំបើក macro ក្នុងឯកសារពីមនុស្សមិនស្គាល់។",
            "ធ្វើបច្ចុប្បន្នភាពទូរស័ព្ទ/កុំព្យូទ័រ និងកម្មវិធីជានិច្ច។",
            "ស្កេនឯកសារមុនបើក (ដូចអ្នកទើបតែធ្វើ!)។",
            "ប្រើពាក្យសម្ងាត់រឹងមាំ ខុសៗគ្នា និងការផ្ទៀងផ្ទាត់ ២ ជំហាន។",
        ],
        "file_title": "📄 ព័ត៌មានឯកសារ",
        "f_name": "ឈ្មោះ", "f_type": "ប្រភេទ", "f_size": "ទំហំ",
        "f_first": "ឃើញលើកដំបូងលើអ៊ីនធឺណិត", "f_last": "ស្កេនចុងក្រោយ",
        "f_times": "ចំនួនដងដែលបានបញ្ជូន",
        "f_votes": "ការបោះឆ្នោតសហគមន៍៖ 👍 {good} សុវត្ថិភាព / 👎 {bad} មេរោគ",
        "f_tags": "ស្លាក",
        "net_title": "🌐 ព័ត៌មានបណ្តាញ (បានកែរូបរាងកុំឱ្យចុចបាន)",
        "net_ips": "📍 អាសយដ្ឋាន IP ដែលវាទាក់ទង៖",
        "net_domains": "🔗 Domain ដែលវាទាក់ទង៖",
        "net_urls": "🕸️ URL ដែលវាទាក់ទង៖",
        "net_flagged": "រកឃើញដោយ {n}",
        "net_none": ("មិនមានសកម្មភាពបណ្តាញត្រូវបានកត់ត្រាទេ។ ឯកសារនេះប្រហែលជា"
                     "មិនទាន់ត្រូវបានដំណើរការក្នុង sandbox ឬវាមិនភ្ជាប់ទៅណាទេ។"),
        "beh_title": "🧪 ឥរិយាបថ (អ្វីដែលវាធ្វើពេលដំណើរការក្នុង sandbox)",
        "beh_tags": "ស្លាកឥរិយាបថ",
        "beh_mitre": "បច្ចេកទេសវាយប្រហារ (MITRE ATT&CK)៖",
        "beh_cmds": "ពាក្យបញ្ជាដែលវាបានដំណើរការ៖",
        "beh_files": "ឯកសារដែលវាបានបង្កើត៖",
        "beh_regs": "Registry keys ដែលវាបានកែប្រែ៖",
        "beh_none": "មិនទាន់មានរបាយការណ៍ឥរិយាបថពី sandbox សម្រាប់ឯកសារនេះទេ។",
        "det_title": "🔬 ការរកឃើញដោយកម្មវិធីកំចាត់មេរោគ (កំពូល)",
    },
}

# Explanations keyed by the malware category VirusTotal reports.
EXPLAIN = {
    "ransomware": {"level": "CRITICAL",
        "en": "Locks or encrypts your photos, documents and other files, then "
              "demands money to unlock them. It can also delete backups and "
              "spread across your network.",
        "km": "ចាក់សោ ឬអ៊ិនគ្រីបរូបថត ឯកសារ និងទិន្នន័យរបស់អ្នក រួចទាមទារលុយដើម្បីដោះសោ។ "
              "វាអាចលុបឯកសារបម្រុងទុក និងរាលដាលតាមបណ្តាញ។"},
    "trojan": {"level": "HIGH",
        "en": "Disguises itself as a normal program or file. Once you run it, it "
              "can give an attacker access to your device, steal data, or "
              "download more malware without you noticing.",
        "km": "ក្លែងខ្លួនជាកម្មវិធី ឬឯកសារធម្មតា។ ពេលអ្នកបើកវា វាអាចអនុញ្ញាតឱ្យហេគ័រចូល"
              "ឧបករណ៍ ដកយកទិន្នន័យ ឬទាញយកមេរោគផ្សេងទៀត ដោយអ្នកមិនដឹង។"},
    "spyware": {"level": "HIGH",
        "en": "Secretly watches you: it can record keystrokes, take screenshots, "
              "copy messages and browsing history, and steal saved logins and "
              "chat sessions (including Telegram).",
        "km": "ឃ្លាំមើលអ្នកដោយសម្ងាត់៖ កត់ត្រាអ្វីដែលអ្នកវាយ ថតអេក្រង់ ចម្លងសារ និង"
              "ប្រវត្តិរុករក ហើយលួចគណនីដែលបានរក្សាទុក និង session ជជែក (រួមទាំង Telegram)។"},
    "stealer": {"level": "CRITICAL",
        "en": "Steals saved passwords, browser cookies, crypto wallets and app "
              "sessions. A stolen Telegram session lets an attacker open your "
              "account without your password.",
        "km": "លួចពាក្យសម្ងាត់ដែលបានរក្សាទុក cookies កាបូបគ្រីបតូ និង session កម្មវិធី។ "
              "ប្រសិនបើ session Telegram ត្រូវបានលួច ហេគ័រអាចចូលគណនីអ្នកដោយមិនត្រូវការ"
              "ពាក្យសម្ងាត់។"},
    "infostealer": {"level": "CRITICAL",
        "en": "Same as a stealer: harvests passwords, cookies and sessions and "
              "sends them to the attacker.",
        "km": "ដូច stealer៖ ប្រមូលពាក្យសម្ងាត់ cookies និង session ហើយបញ្ជូនទៅហេគ័រ។"},
    "backdoor": {"level": "CRITICAL",
        "en": "Opens a hidden door so an attacker can control your device "
              "remotely, run commands and install more malware.",
        "km": "បើកទ្វារសម្ងាត់ឱ្យហេគ័រគ្រប់គ្រងឧបករណ៍អ្នកពីចម្ងាយ បញ្ជាឱ្យដំណើរការ "
              "និងដំឡើងមេរោគបន្ថែម។"},
    "rat": {"level": "CRITICAL",
        "en": "Remote Access Trojan: the attacker can see your screen, read your "
              "files, use your webcam and microphone, and run commands.",
        "km": "Remote Access Trojan៖ ហេគ័រអាចមើលអេក្រង់ អានឯកសារ ប្រើកាមេរ៉ា និង"
              "មីក្រូហ្វូនរបស់អ្នក ហើយដំណើរការពាក្យបញ្ជា។"},
    "worm": {"level": "HIGH",
        "en": "Spreads by itself to other devices, networks or contacts without "
              "needing you to do anything.",
        "km": "រាលដាលដោយខ្លួនឯងទៅឧបករណ៍ បណ្តាញ ឬអ្នកទំនាក់ទំនងផ្សេងទៀត "
              "ដោយមិនចាំបាច់ឱ្យអ្នកធ្វើអ្វីឡើយ។"},
    "virus": {"level": "HIGH",
        "en": "Infects other files on your device and spreads when they are "
              "shared. Can corrupt data and slow the system.",
        "km": "ឆ្លងទៅឯកសារផ្សេងទៀតលើឧបករណ៍ ហើយរាលដាលនៅពេលឯកសារទាំងនោះត្រូវបាន"
              "ចែករំលែក។ អាចបំផ្លាញទិន្នន័យ និងធ្វើឱ្យប្រព័ន្ធយឺត។"},
    "exploit": {"level": "HIGH",
        "en": "Abuses a bug in your software to run malicious code, often "
              "silently. Keeping your system updated blocks many of these.",
        "km": "ប្រើប្រាស់កំហុសក្នុងកម្មវិធីរបស់អ្នក ដើម្បីដំណើរការកូដអាក្រក់ ជាញឹកញាប់"
              "ដោយស្ងាត់ស្ងៀម។ ការធ្វើបច្ចុប្បន្នភាពជួយទប់ស្កាត់បានច្រើន។"},
    "hacktool": {"level": "MEDIUM",
        "en": "A hacker tool (password cracker, scanner, etc.). Not always a "
              "virus by itself, but often used or installed by attackers.",
        "km": "ឧបករណ៍ហេគ័រ (ទម្លាយពាក្យសម្ងាត់ ស្កេនបណ្តាញ ។ល។)។ មិនមែនជាមេរោគជានិច្ចទេ "
              "ប៉ុន្តែតែងត្រូវបានហេគ័រប្រើ ឬដំឡើង។"},
    "banker": {"level": "CRITICAL",
        "en": "Targets online banking: steals card and bank logins and can alter "
              "transactions.",
        "km": "ផ្តោតលើធនាគារអនឡាញ៖ លួចគណនីធនាគារ និងកាត ហើយអាចកែប្រែប្រតិបត្តិការ។"},
    "botnet": {"level": "HIGH",
        "en": "Turns your device into a remote-controlled zombie used to attack "
              "others or send spam.",
        "km": "ប្រែឧបករណ៍អ្នកទៅជា 'សូមប៊ី' ដែលត្រូវបានគ្រប់គ្រងពីចម្ងាយ ដើម្បីវាយប្រហារ"
              "អ្នកដទៃ ឬផ្ញើសារឥតបានការ។"},
    "miner": {"level": "MEDIUM",
        "en": "Secretly uses your CPU/GPU to mine cryptocurrency. Slows your "
              "device, raises heat and electricity use. Mostly not data-stealing.",
        "km": "លួចប្រើ CPU/GPU របស់អ្នកដើម្បីជីកគ្រីបតូ។ ធ្វើឱ្យឧបករណ៍យឺត ក្តៅ និងស៊ីភ្លើង"
              "ច្រើន។ ភាគច្រើនមិនលួចទិន្នន័យទេ។"},
    "coinminer": {"level": "MEDIUM",
        "en": "Secretly uses your CPU/GPU to mine cryptocurrency and slows your "
              "device.",
        "km": "លួចប្រើ CPU/GPU របស់អ្នកដើម្បីជីកគ្រីបតូ ហើយធ្វើឱ្យឧបករណ៍យឺត។"},
    "adware": {"level": "LOW",
        "en": "Shows unwanted ads and pop-ups and may change browser settings or "
              "track what you browse.",
        "km": "បង្ហាញការផ្សាយពាណិជ្ជកម្មដែលមិនចង់បាន ហើយអាចប្តូរការកំណត់កម្មវិធីរុករក "
              "ឬតាមដានអ្វីដែលអ្នករុករក។"},
    "downloader": {"level": "HIGH",
        "en": "A small program whose job is to download and install other, worse "
              "malware.",
        "km": "កម្មវិធីតូចមួយដែលមានតួនាទីទាញយក និងដំឡើងមេរោគដទៃដែលអាក្រក់ជាង។"},
    "dropper": {"level": "HIGH",
        "en": "Carries other malware inside it and installs it secretly.",
        "km": "ផ្ទុកមេរោគដទៃនៅខាងក្នុង ហើយដំឡើងវាដោយសម្ងាត់។"},
    "keylogger": {"level": "HIGH",
        "en": "Records everything you type, including passwords and private "
              "messages.",
        "km": "កត់ត្រាអ្វីៗទាំងអស់ដែលអ្នកវាយ រួមទាំងពាក្យសម្ងាត់ និងសារឯកជន។"},
    "rootkit": {"level": "CRITICAL",
        "en": "Hides deep inside the system so it is very hard to find and "
              "remove.",
        "km": "លាក់ខ្លួនជ្រៅក្នុងប្រព័ន្ធ ពិបាករក និងពិបាកលុបចោលណាស់។"},
    "pua": {"level": "LOW",
        "en": "Potentially unwanted app: not strictly a virus, but unwanted and "
              "risky (bundled software, toolbars, trackers).",
        "km": "កម្មវិធីដែលមិនចង់បាន៖ មិនមែនជាមេរោគពិតប្រាកដទេ ប៉ុន្តែគ្មានប្រយោជន៍ និង"
              "ប្រថុយប្រថាន (កម្មវិធីភ្ជាប់មកជាមួយ toolbar ឧបករណ៍តាមដាន)។"},
}

_STEAL = {
    "en": "Treat every saved password and logged-in session as stolen. Log out "
          "everywhere and change passwords.",
    "km": "ចាត់ទុកថាពាក្យសម្ងាត់ និង session ដែលបានរក្សាទុកទាំងអស់ត្រូវបានលួច។ "
          "ចាកចេញគ្រប់ទីកន្លែង ហើយប្តូរពាក្យសម្ងាត់។",
}

# Extra advice for specific malware types.
EXTRA_ADVICE = {
    "ransomware": {
        "en": "Do NOT pay the ransom. Keep the device off the network, don't "
              "delete the encrypted files, restore from a backup, and check "
              "nomoreransom.org for free decryptors.",
        "km": "កុំបង់ប្រាក់ដែលគេទារ។ ដកឧបករណ៍ចេញពីបណ្តាញ កុំលុបឯកសារដែលត្រូវអ៊ិនគ្រីប "
              "ស្តារពីឯកសារបម្រុងទុក ហើយពិនិត្យ nomoreransom.org សម្រាប់ឧបករណ៍ដោះសោ"
              "ឥតគិតថ្លៃ។"},
    "backdoor": {
        "en": "Assume someone had remote control of the device. Change all "
              "passwords from a different, clean device.",
        "km": "សន្មតថាមាននរណាម្នាក់គ្រប់គ្រងឧបករណ៍អ្នកពីចម្ងាយ។ ប្តូរពាក្យសម្ងាត់ទាំងអស់"
              "ពីឧបករណ៍ផ្សេងដែលស្អាត។"},
    "rat": {
        "en": "Assume someone could see your screen and files. Cover the webcam, "
              "disconnect, and change all passwords from a different device.",
        "km": "សន្មតថាមាននរណាម្នាក់អាចមើលអេក្រង់ និងឯកសាររបស់អ្នក។ គ្របកាមេរ៉ា "
              "ផ្តាច់អ៊ីនធឺណិត ហើយប្តូរពាក្យសម្ងាត់ទាំងអស់ពីឧបករណ៍ផ្សេង។"},
    "spyware": {
        "en": "Treat everything you typed or saved on this device as seen by "
              "someone else.",
        "km": "ចាត់ទុកថាអ្វីៗដែលអ្នកវាយ ឬរក្សាទុកលើឧបករណ៍នេះ អាចត្រូវបានគេឃើញ។"},
    "stealer": _STEAL,
    "infostealer": _STEAL,
    "keylogger": {
        "en": "Anything you typed (passwords, messages, card numbers) may be "
              "stolen. Change them from a clean device.",
        "km": "អ្វីៗដែលអ្នកវាយ (ពាក្យសម្ងាត់ សារ លេខកាត) អាចត្រូវបានលួច។ "
              "ប្តូរវាពីឧបករណ៍ដែលស្អាត។"},
    "banker": {
        "en": "Call your bank, check recent transactions and consider freezing "
              "your cards.",
        "km": "ទូរស័ព្ទទៅធនាគារ ពិនិត្យប្រតិបត្តិការថ្មីៗ ហើយពិចារណាទប់ស្កាត់កាតរបស់អ្នក។"},
    "miner": {
        "en": "Open Activity Monitor (Mac) or Task Manager (Windows) and look for "
              "a process using lots of CPU.",
        "km": "បើក Activity Monitor (Mac) ឬ Task Manager (Windows) ហើយរកដំណើរការណា"
              "ដែលប្រើ CPU ច្រើន។"},
}


def tr(lang: str, key: str, **kw) -> str:
    text = S.get(lang, S[DEFAULT_LANG])[key]
    return text.format(**kw) if kw else text


# ---------- helpers ----------
def defang(text) -> str:
    """Make links/IPs unclickable so nobody opens them by accident."""
    return str(text).replace("http", "hxxp").replace(".", "[.]")


def short(text, n=90) -> str:
    text = str(text).replace("\n", " ")
    return text if len(text) <= n else text[: n - 1] + "…"


def fmt_date(ts, lang: str) -> str:
    if not ts:
        return tr(lang, "unknown")
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def items(resp) -> list:
    return resp.get("data", []) if isinstance(resp, dict) else []


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


async def send_long(message, text: str):
    """Telegram rejects messages over 4096 chars, so split long reports."""
    while text:
        if len(text) <= TG_LIMIT:
            await message.reply_text(text)
            return
        cut = text.rfind("\n\n", 0, TG_LIMIT)
        if cut <= 0:
            cut = text.rfind("\n", 0, TG_LIMIT)
        if cut <= 0:
            cut = TG_LIMIT
        await message.reply_text(text[:cut])
        text = text[cut:].lstrip("\n")


# ---------- VirusTotal calls ----------
async def vt_get(client: httpx.AsyncClient, path: str, retries: int = 2):
    """GET from VirusTotal. Waits and retries if the free-tier rate limit hits."""
    for attempt in range(retries + 1):
        try:
            r = await client.get(f"{VT}{path}", headers=HEADERS)
        except httpx.HTTPError:
            return None
        if r.status_code == 200:
            return r.json()
        if r.status_code == 429 and attempt < retries:
            await asyncio.sleep(20)
            continue
        return None
    return None


async def vt_upload_and_wait(client: httpx.AsyncClient, path: str, sha: str):
    with open(path, "rb") as f:
        r = await client.post(f"{VT}/files", headers=HEADERS, files={"file": f})
    r.raise_for_status()
    for _ in range(12):  # poll up to ~2 minutes
        await asyncio.sleep(10)
        report = await vt_get(client, f"/files/{sha}", retries=0)
        if report and report["data"]["attributes"].get("last_analysis_results"):
            return report
    return None


async def fetch_extras(client: httpx.AsyncClient, sha: str) -> dict:
    """IPs, domains, URLs and sandbox behaviour (only fetched for flagged files)."""
    return {
        "ips": await vt_get(client, f"/files/{sha}/contacted_ips?limit=10"),
        "domains": await vt_get(client, f"/files/{sha}/contacted_domains?limit=10"),
        "urls": await vt_get(client, f"/files/{sha}/contacted_urls?limit=5"),
        "behaviour": await vt_get(client, f"/files/{sha}/behaviour_summary"),
    }


# ---------- report sections ----------
def file_info(a: dict, lang: str) -> str:
    names = a.get("names") or []
    name = a.get("meaningful_name") or (names[0] if names else tr(lang, "unknown"))
    votes = a.get("total_votes", {})
    lines = [
        tr(lang, "file_title"),
        f"{tr(lang, 'f_name')}: {short(name, 60)}",
        f"{tr(lang, 'f_type')}: {a.get('type_description', tr(lang, 'unknown'))}",
        f"{tr(lang, 'f_size')}: {round(a.get('size', 0) / 1024, 1)} KB",
        f"MD5: {a.get('md5', '?')}",
        f"SHA-256: {a.get('sha256', '?')}",
        f"{tr(lang, 'f_first')}: {fmt_date(a.get('first_submission_date'), lang)}",
        f"{tr(lang, 'f_last')}: {fmt_date(a.get('last_analysis_date'), lang)}",
        f"{tr(lang, 'f_times')}: {a.get('times_submitted', '?')}",
        tr(lang, "f_votes", good=votes.get("harmless", 0),
           bad=votes.get("malicious", 0)),
    ]
    if a.get("tags"):
        lines.append(f"{tr(lang, 'f_tags')}: " + ", ".join(a["tags"][:8]))
    return "\n".join(lines)


def type_section(a: dict, bad: int, lang: str):
    cls = a.get("popular_threat_classification", {})
    label = cls.get("suggested_threat_label", "unknown")
    cats = [c["value"].lower() for c in cls.get("popular_threat_category", [])]
    families = [n["value"] for n in cls.get("popular_threat_name", [])]
    if not cats and label != "unknown":
        cats = [label.split(".")[0].split("/")[0].lower()]

    type_name = " / ".join(c.upper() for c in cats) if cats \
        else tr(lang, "type_unknown")
    lines = [tr(lang, "type_title", t=type_name),
             tr(lang, "detected_as", label=label)]
    if families:
        lines.append(tr(lang, "family", f=", ".join(families[:3])))

    worst, explained = None, []
    for c in cats:
        info = EXPLAIN.get(c)
        if info:
            explained.append(f"• {c.capitalize()}: {info[lang]}")
            if worst is None or ORDER.index(info["level"]) > ORDER.index(worst):
                worst = info["level"]
    if worst is None:
        worst = "HIGH" if bad >= 10 else "MEDIUM"

    lines.append("\n" + tr(lang, "danger_level", lvl=LEVELS[lang][worst]))
    lines.append("\n" + tr(lang, "what_title"))
    lines.extend(explained if explained else [tr(lang, "no_type")])
    return "\n".join(lines), cats


def advice_section(cats: list, lang: str) -> str:
    lines = [tr(lang, "advice_title")]
    lines += [f"{i}. {step}" for i, step in enumerate(S[lang]["advice_steps"], 1)]
    extras = [EXTRA_ADVICE[c][lang] for c in dict.fromkeys(cats)
              if c in EXTRA_ADVICE]
    if extras:
        lines.append("\n" + tr(lang, "specific_title"))
        lines.extend(f"• {e}" for e in extras)
    lines.append("\n" + tr(lang, "prevent_title"))
    lines.extend(f"• {p}" for p in S[lang]["prevent_items"])
    return "\n".join(lines)


def network_section(extras: dict, lang: str) -> str:
    lines = [tr(lang, "net_title")]
    found = False

    ips = items(extras.get("ips"))
    if ips:
        found = True
        lines.append("\n" + tr(lang, "net_ips"))
        for i in ips[:10]:
            at = i.get("attributes", {})
            flagged = at.get("last_analysis_stats", {}).get("malicious", 0)
            lines.append(f"• {defang(i.get('id', '?'))} | "
                         f"{at.get('country', '?')} | "
                         f"{short(at.get('as_owner', '?'), 40)} | "
                         f"{tr(lang, 'net_flagged', n=flagged)}")

    doms = items(extras.get("domains"))
    if doms:
        found = True
        lines.append("\n" + tr(lang, "net_domains"))
        for d in doms[:10]:
            flagged = d.get("attributes", {}).get(
                "last_analysis_stats", {}).get("malicious", 0)
            lines.append(f"• {defang(d.get('id', '?'))} | "
                         f"{tr(lang, 'net_flagged', n=flagged)}")

    urls = items(extras.get("urls"))
    if urls:
        found = True
        lines.append("\n" + tr(lang, "net_urls"))
        for u in urls[:5]:
            at = u.get("attributes", {})
            lines.append(f"• {short(defang(at.get('url', u.get('id', '?'))), 90)}")

    if not found:
        lines.append(tr(lang, "net_none"))
    return "\n".join(lines)


def behaviour_section(extras: dict, a: dict, lang: str) -> str:
    b = (extras.get("behaviour") or {}).get("data")
    lines = [tr(lang, "beh_title")]
    found = False

    sv = a.get("sandbox_verdicts") or {}
    for sandbox, v in list(sv.items())[:3]:
        found = True
        names = ", ".join((v.get("malware_names") or [])[:3])
        lines.append(f"• {sandbox}: {v.get('category', '?')}"
                     + (f" ({names})" if names else ""))

    if isinstance(b, dict):
        if b.get("tags"):
            found = True
            lines.append(f"{tr(lang, 'beh_tags')}: " + ", ".join(b["tags"][:8]))

        mitre = b.get("mitre_attack_techniques") or []
        if mitre:
            found = True
            lines.append("\n" + tr(lang, "beh_mitre"))
            for t in mitre[:6]:
                sev = str(t.get("severity", "")).replace("IMPACT_SEVERITY_", "")
                lines.append(f"• {t.get('id', '?')}: "
                             f"{short(t.get('signature_description', ''), 80)} "
                             f"({sev})")

        cmds = b.get("command_executions") or []
        if cmds:
            found = True
            lines.append("\n" + tr(lang, "beh_cmds"))
            lines.extend(f"• {short(c, 100)}" for c in cmds[:3])

        written = b.get("files_written") or []
        if written:
            found = True
            lines.append("\n" + tr(lang, "beh_files"))
            lines.extend(f"• {short(w, 100)}" for w in written[:5])

        regs = b.get("registry_keys_set") or []
        if regs:
            found = True
            lines.append("\n" + tr(lang, "beh_regs"))
            for r in regs[:3]:
                key = r.get("key", r) if isinstance(r, dict) else r
                lines.append(f"• {short(key, 100)}")

    if not found:
        lines.append(tr(lang, "beh_none"))
    return "\n".join(lines)


def detections_section(a: dict, lang: str) -> str:
    results = a.get("last_analysis_results", {})
    hits = [f"• {eng}: {short(r['result'], 50)}" for eng, r in results.items()
            if r.get("category") == "malicious" and r.get("result")]
    if not hits:
        return ""
    return tr(lang, "det_title") + "\n" + "\n".join(hits[:8])


def build_report(data: dict, extras: dict, lang: str = DEFAULT_LANG) -> str:
    a = data["data"]["attributes"]
    stats = a.get("last_analysis_stats", {})
    bad = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    total = sum(stats.values())
    flagged = bad + sus

    if flagged == 0:
        return "\n\n".join([
            tr(lang, "v_clean", total=total),
            file_info(a, lang),
            tr(lang, "clean_note"),
            tr(lang, "thanks"),
        ])

    if bad >= 10:
        verdict = tr(lang, "v_danger")
    elif bad >= 3:
        verdict = tr(lang, "v_likely")
    else:
        verdict = tr(lang, "v_sus")

    types_text, cats = type_section(a, bad, lang)
    parts = [
        f"{verdict}\n{tr(lang, 'flagged_by', n=flagged, total=total)}",
        types_text,
        advice_section(cats, lang),
        file_info(a, lang),
        network_section(extras, lang),
        behaviour_section(extras, a, lang),
        detections_section(a, lang),
        tr(lang, "thanks"),
    ]
    return "\n\n".join(p for p in parts if p)


# ---------- Telegram handlers ----------
def get_lang(context: ContextTypes.DEFAULT_TYPE) -> str:
    return context.user_data.get("lang", DEFAULT_LANG)


def lang_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("🇬🇧 English", callback_data="lang:en"),
        InlineKeyboardButton("🇰🇭 ខ្មែរ", callback_data="lang:km"),
    ]])


async def ask_language(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(S["en"]["choose_lang"],
                                    reply_markup=lang_keyboard())


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if "lang" in context.user_data:
        await update.message.reply_text(tr(get_lang(context), "welcome"))
    else:
        await ask_language(update, context)


async def on_language(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    lang = query.data.split(":", 1)[1]
    if lang not in S:
        return
    context.user_data["lang"] = lang
    await query.edit_message_text(tr(lang, "lang_set"))
    await query.message.reply_text(tr(lang, "welcome"))


async def hint(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(tr(get_lang(context), "hint"))


async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    lang = get_lang(context)
    doc = update.message.document
    if doc.file_size and doc.file_size > MAX_BYTES:
        await update.message.reply_text(tr(lang, "too_big"))
        return

    await update.message.reply_text(tr(lang, "scanning"))
    try:
        tg_file = await context.bot.get_file(doc.file_id)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sample.bin")  # never executed or opened
            await tg_file.download_to_drive(path)
            sha = sha256_of(path)

            async with httpx.AsyncClient(timeout=60) as client:
                report = await vt_get(client, f"/files/{sha}")  # known file?
                if report is None:
                    report = await vt_upload_and_wait(client, path, sha)

                extras = {}
                if report is not None:
                    st = report["data"]["attributes"].get("last_analysis_stats", {})
                    if st.get("malicious", 0) + st.get("suspicious", 0) > 0:
                        await update.message.reply_text(tr(lang, "collecting"))
                        extras = await fetch_extras(client, sha)
    except Exception as e:  # keep the bot alive on any failure
        print("Scan error:", repr(e))
        await update.message.reply_text(tr(lang, "error"))
        return

    if report is None:
        await update.message.reply_text(tr(lang, "timeout"))
        return

    await send_long(update.message, build_report(report, extras, lang))


def main():
    # PicklePersistence remembers each user's language between restarts
    # (it resets if the host wipes its disk on redeploy).
    persistence = PicklePersistence(filepath="bot_data.pkl")
    app = (ApplicationBuilder().token(TELEGRAM_TOKEN)
           .persistence(persistence).build())
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", start))
    app.add_handler(CommandHandler("language", ask_language))
    app.add_handler(CallbackQueryHandler(on_language, pattern=r"^lang:"))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    app.add_handler(MessageHandler(
        filters.PHOTO | filters.VIDEO | filters.AUDIO
        | (filters.TEXT & ~filters.COMMAND), hint))
    app.run_polling()


if __name__ == "__main__":
    main()