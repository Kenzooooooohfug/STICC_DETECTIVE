"""
STICC_DETECTIVE - Telegram file/link scanner bot (VirusTotal), English + Khmer.
Short reports + "More info" button, and Auto Protection for groups and
Telegram Business chats (silent unless something is dangerous).

Optional env vars:
  MAX_FILE_MB  max file size in MB (default 20; above 20 needs BOT_API_URL)
  BOT_API_URL  address of a self-hosted Telegram Bot API server

Install:  pip install python-telegram-bot httpx
Env vars: TELEGRAM_TOKEN (from @BotFather), VT_API_KEY (from virustotal.com)
Run:      python scanner_bot.py
"""
import asyncio
import base64
import hashlib
import html
import os
import tempfile
from datetime import datetime, timezone

import httpx
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (ApplicationBuilder, CallbackQueryHandler,
                          CommandHandler, ContextTypes, MessageHandler,
                          PicklePersistence, TypeHandler, filters)

TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
VT_API_KEY = os.environ["VT_API_KEY"]
VT = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY}
BOT_API_URL = os.environ.get("BOT_API_URL", "").rstrip("/")  # optional local server
MAX_MB = int(os.environ.get("MAX_FILE_MB", "20"))
if not BOT_API_URL:
    MAX_MB = min(MAX_MB, 20)  # Telegram's cloud Bot API only allows 20 MB
MAX_BYTES = MAX_MB * 1024 * 1024
ALERT_MIN = 3  # alert only when this many engines say "malicious"
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
            "Limits: {max_mb} MB max per file.\n"
            "🔒 Privacy: scanned files are shared with VirusTotal, so don't send "
            "private documents.\n\n"
            "🛡️ Auto Protection: add me to a group or connect me in Telegram Business and I will only speak up when a file is dangerous.\n\n"
            "⚙️ Language and settings: /settings\n\n"
            "Go ahead, send me a file!"),
        "hint": ("📎 Send me a file (paperclip → File) or a link and I'll scan "
                 "it. Photos and plain text can't be scanned."),
        "too_big": "File is too big (limit {max_mb} MB).",
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
        "settings_text": (
            "⚙️ Settings\n\n"
            "🔒 Private chat settings\n"
            "Check links and files that other people send you. Your own outgoing "
            "messages, plain message text and ordinary photos are all ignored.\n\n"
            "To turn this on, connect me in Telegram: Settings → Telegram "
            "Business → Chatbots → add me."),
        "set_lang_btn": "🌐 Language: English",
        "set_files": "📁 Scan files",
        "set_links": "🔗 Scan links",
        "on": "ON ✅",
        "off": "OFF ❌",
        "l_danger": "🚨 DANGEROUS LINK: do not open it!",
        "l_sus": "⚠️ SUSPICIOUS LINK: be careful.",
        "l_clean": "✅ No threats found in this link.",
        "l_url": "Link: {u}",
        "l_flagged": "Flagged by {n}/{total} engines.",
        "l_det": "Top detections:",
        "l_advice": "Don't open it, and never enter a password or code on it.",
        "l_clean_note": ("Not a guarantee. Check the address carefully before "
                         "logging in anywhere."),
        "l_error": "⚠️ Couldn't scan this link. Try again in a minute.",
        "b_connected": ("✅ Connected to your private chats. I'll check links and "
                        "files other people send you and message you the result "
                        "here.\n\nChange this anytime in /settings"),
        "b_disconnected": "Disconnected from your private chats.",
        "b_from": "📨 Sent by {who}",
        "r_level": "DANGER LEVEL: {lvl}",
        "r_sus": "SUSPICIOUS FILE",
        "r_clean": "CLEAN",
        "r_type": "VIRUS TYPE",
        "r_file": "FILE",
        "r_det": "DETECTED BY",
        "r_does": "WHAT IT CAN DO",
        "r_ip": "IP ADDRESS",
        "r_noip": "no IP data yet",
        "r_opened": "IF YOU OPENED IT",
        "r_tip": "TIP",
        "short_opened": ("Disconnect from the internet → delete the file → change "
                         "your passwords from another device → end all other "
                         "Telegram sessions (Settings > Devices)."),
        "short_tip": "Only open files from people you trust, and scan before opening.",
        "btn_more": "📋 More info",
        "full_title": "📋 FULL DETAILS",
        "more_missing": "Those details are no longer available. Please send the file to me again.",
        "upload_failed": ("⚠️ VirusTotal could not accept this file (it may be too "
                          "large for the free plan). Try a smaller file."),
        "a_file": "🔴 WARNING: THIS FILE IS NOT SAFE",
        "a_do": "Do not open it.",
        "set_deep": "🔬 Upload unknown files",
        "g_settings_text": (
            "⚙️ Group protection\n\n"
            "I quietly check files and links shared in this group and only speak "
            "up when something is dangerous.\n"
            "Only group admins can change these settings."),
        "admin_only": "Only group admins can change these settings.",
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
            "កំណត់៖ ឯកសារអតិបរមា {max_mb} MB។\n"
            "🔒 ឯកជនភាព៖ ឯកសារដែលស្កេនត្រូវបានចែករំលែកជាមួយ VirusTotal "
            "ដូច្នេះសូមកុំផ្ញើឯកសារឯកជន។\n\n"
            "🛡️ ការការពារស្វ័យប្រវត្តិ៖ បន្ថែមខ្ញុំទៅក្នុងក្រុម ឬភ្ជាប់ខ្ញុំក្នុង Telegram Business ហើយខ្ញុំនឹងនិយាយតែពេលឯកសារមានគ្រោះថ្នាក់ប៉ុណ្ណោះ។\n\n"
            "⚙️ ភាសា និងការកំណត់៖ /settings\n\n"
            "សូមផ្ញើឯកសារមកខ្ញុំបាន!"),
        "hint": ("📎 សូមផ្ញើឯកសារ (ចុច 📎 → File) ឬតំណភ្ជាប់ ដើម្បីឱ្យខ្ញុំស្កេន។ "
                 "រូបថត និងអក្សរធម្មតាមិនអាចស្កេនបានទេ។"),
        "too_big": "ឯកសារធំពេក (កំណត់ត្រឹម {max_mb} MB)។",
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
        "settings_text": (
            "⚙️ ការកំណត់\n\n"
            "🔒 ការកំណត់ការជជែកឯកជន\n"
            "ពិនិត្យតំណភ្ជាប់ និងឯកសារដែលអ្នកដទៃផ្ញើមកអ្នក។ សារដែលអ្នកផ្ញើខ្លួនឯង "
            "អក្សរធម្មតា និងរូបថតធម្មតា នឹងត្រូវមិនអើពើទាំងអស់។\n\n"
            "ដើម្បីបើកមុខងារនេះ សូមភ្ជាប់ខ្ញុំក្នុង Telegram៖ Settings → Telegram "
            "Business → Chatbots → បន្ថែមខ្ញុំ។"),
        "set_lang_btn": "🌐 ភាសា៖ ខ្មែរ",
        "set_files": "📁 ស្កេនឯកសារ",
        "set_links": "🔗 ស្កេនតំណភ្ជាប់",
        "on": "បើក ✅",
        "off": "បិទ ❌",
        "l_danger": "🚨 តំណភ្ជាប់គ្រោះថ្នាក់៖ សូមកុំបើកវា!",
        "l_sus": "⚠️ តំណភ្ជាប់គួរឱ្យសង្ស័យ៖ សូមប្រយ័ត្ន។",
        "l_clean": "✅ រកមិនឃើញការគំរាមកំហែងក្នុងតំណភ្ជាប់នេះទេ។",
        "l_url": "តំណភ្ជាប់៖ {u}",
        "l_flagged": "រកឃើញដោយ {n}/{total} ម៉ាស៊ីនស្កេន។",
        "l_det": "ការរកឃើញកំពូល៖",
        "l_advice": "កុំបើកវា ហើយកុំបញ្ចូលពាក្យសម្ងាត់ ឬកូដណាមួយនៅលើវា។",
        "l_clean_note": ("មិនមែនជាការធានាទេ។ សូមពិនិត្យអាសយដ្ឋានឱ្យបានល្អិតល្អន់មុន"
                         "ចូលគណនីនៅកន្លែងណាមួយ។"),
        "l_error": "⚠️ មិនអាចស្កេនតំណភ្ជាប់នេះបានទេ។ សូមព្យាយាមម្តងទៀតក្នុងរយៈពេលមួយនាទី។",
        "b_connected": ("✅ បានភ្ជាប់ជាមួយការជជែកឯកជនរបស់អ្នក។ ខ្ញុំនឹងពិនិត្យតំណភ្ជាប់ "
                        "និងឯកសារដែលអ្នកដទៃផ្ញើមកអ្នក ហើយផ្ញើលទ្ធផលមកទីនេះ។\n\n"
                        "ប្តូរបានគ្រប់ពេលក្នុង /settings"),
        "b_disconnected": "បានផ្តាច់ពីការជជែកឯកជនរបស់អ្នក។",
        "b_from": "📨 ផ្ញើដោយ {who}",
        "r_level": "កម្រិតគ្រោះថ្នាក់៖ {lvl}",
        "r_sus": "ឯកសារគួរឱ្យសង្ស័យ",
        "r_clean": "សុវត្ថិភាព",
        "r_type": "ប្រភេទមេរោគ",
        "r_file": "ឯកសារ",
        "r_det": "រកឃើញដោយ",
        "r_does": "អ្វីដែលវាអាចធ្វើបាន",
        "r_ip": "អាសយដ្ឋាន IP",
        "r_noip": "មិនទាន់មានទិន្នន័យ IP",
        "r_opened": "ប្រសិនបើអ្នកបានបើកវា",
        "r_tip": "ដំបូន្មាន",
        "short_opened": ("កាត់ផ្តាច់អ៊ីនធឺណិត → លុបឯកសារ → ប្តូរពាក្យសម្ងាត់ពីឧបករណ៍ផ្សេង "
                         "→ បញ្ចប់ session Telegram ផ្សេងទាំងអស់ (Settings > Devices)។"),
        "short_tip": "បើកតែឯកសារពីមនុស្សដែលអ្នកទុកចិត្ត ហើយស្កេនមុនបើក។",
        "btn_more": "📋 ព័ត៌មានបន្ថែម",
        "full_title": "📋 ព័ត៌មានលម្អិតទាំងអស់",
        "more_missing": "ព័ត៌មានទាំងនោះលែងមានទៀតហើយ។ សូមផ្ញើឯកសារមកខ្ញុំម្តងទៀត។",
        "upload_failed": ("⚠️ VirusTotal មិនអាចទទួលឯកសារនេះបានទេ (វាអាចធំពេកសម្រាប់"
                          "គម្រោងឥតគិតថ្លៃ)។ សូមសាកល្បងឯកសារតូចជាងនេះ។"),
        "a_file": "🔴 ការព្រមាន៖ ឯកសារនេះមិនមានសុវត្ថិភាព",
        "a_do": "សូមកុំបើកវា។",
        "set_deep": "🔬 ផ្ទុកឡើងឯកសារមិនស្គាល់",
        "g_settings_text": (
            "⚙️ ការការពារក្រុម\n\n"
            "ខ្ញុំពិនិត្យឯកសារ និងតំណភ្ជាប់ក្នុងក្រុមនេះដោយស្ងៀមស្ងាត់ "
            "ហើយនិយាយតែពេលមានអ្វីគ្រោះថ្នាក់ប៉ុណ្ណោះ។\n"
            "មានតែអ្នកគ្រប់គ្រង (admin) ក្រុមទេដែលអាចប្តូរការកំណត់នេះបាន។"),
        "admin_only": "មានតែអ្នកគ្រប់គ្រង (admin) ក្រុមទេដែលអាចប្តូរការកំណត់នេះបាន។",
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
    return text.format(max_mb=MAX_MB, **kw)


# ---------- helpers ----------
LINE = "━━━━━━━━━━━━━━━"
LEVEL_ICON = {"LOW": "🟡", "MEDIUM": "🟠", "HIGH": "🔴", "CRITICAL": "🔴"}
LEVEL_NAME = {
    "en": {"LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"},
    "km": {"LOW": "ទាប", "MEDIUM": "មធ្យម", "HIGH": "ខ្ពស់", "CRITICAL": "ធ្ងន់ធ្ងរបំផុត"},
}
VT_SMALL_LIMIT = 32 * 1024 * 1024  # VirusTotal's normal upload limit
CACHE_MAX = 300
REPORT_CACHE = {}  # sha256 -> VirusTotal file report (used by "More info")
UNIQUE_CACHE = {}  # Telegram file_unique_id -> sha256 (skip re-downloading)


def cache_put(cache: dict, key, value):
    if len(cache) >= CACHE_MAX:
        cache.pop(next(iter(cache)))
    cache[key] = value


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


def first_sentence(text: str, lang: str) -> str:
    sep = "។" if lang == "km" else ". "
    i = text.find(sep)
    return text if i == -1 else text[: i + len(sep)].strip()


def sha_to_token(sha_hex: str) -> str:
    """43-char token for a SHA-256 (fits Telegram's 64-byte button limits)."""
    return base64.urlsafe_b64encode(bytes.fromhex(sha_hex)).decode().rstrip("=")


def token_to_sha(token: str):
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    except Exception:
        return None
    return raw.hex() if len(raw) == 32 else None


async def send_long(send, text: str):
    """Send text via `send(chunk)`, splitting at Telegram's 4096-char limit."""
    while text:
        if len(text) <= TG_LIMIT:
            await send(text)
            return
        cut = text.rfind("\n\n", 0, TG_LIMIT)
        if cut <= 0:
            cut = text.rfind("\n", 0, TG_LIMIT)
        if cut <= 0:
            cut = TG_LIMIT
        await send(text[:cut])
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


async def vt_upload(client: httpx.AsyncClient, path: str, size: int) -> bool:
    url = f"{VT}/files"
    if size > VT_SMALL_LIMIT:  # big files need a special upload URL
        up = await vt_get(client, "/files/upload_url")
        url = up.get("data") if isinstance(up, dict) else None
        if not url:
            return False
    try:
        with open(path, "rb") as f:
            r = await client.post(url, headers=HEADERS, files={"file": f},
                                  timeout=300)
    except httpx.HTTPError:
        return False
    return r.status_code == 200


async def vt_wait(client: httpx.AsyncClient, sha: str, tries: int = 12):
    for _ in range(tries):  # ~2 minutes
        await asyncio.sleep(10)
        report = await vt_get(client, f"/files/{sha}", retries=0)
        if report and report["data"]["attributes"].get("last_analysis_results"):
            return report
    return None


async def vt_file_report(client, path: str, sha: str, size: int, allow_upload: bool):
    """Returns (report, status). Only uploads the file if allow_upload is True."""
    report = await vt_get(client, f"/files/{sha}")
    if report is not None:
        return report, "ok"
    if not allow_upload:
        return None, "unknown"
    if not await vt_upload(client, path, size):
        return None, "upload_failed"
    report = await vt_wait(client, sha)
    return (report, "ok") if report else (None, "timeout")


async def fetch_ips(client: httpx.AsyncClient, sha: str, n: int = 3) -> list:
    return items(await vt_get(client, f"/files/{sha}/contacted_ips?limit={n}"))


async def fetch_full_extras(client: httpx.AsyncClient, sha: str) -> dict:
    return {
        "ips": await vt_get(client, f"/files/{sha}/contacted_ips?limit=10"),
        "domains": await vt_get(client, f"/files/{sha}/contacted_domains?limit=10"),
        "urls": await vt_get(client, f"/files/{sha}/contacted_urls?limit=5"),
        "behaviour": await vt_get(client, f"/files/{sha}/behaviour_summary"),
    }


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


async def vt_scan_url(client: httpx.AsyncClient, url: str):
    uid = url_id(url)
    rep = await vt_get(client, f"/urls/{uid}")  # already known?
    if rep:
        return rep["data"]["attributes"]
    try:
        r = await client.post(f"{VT}/urls", headers=HEADERS, data={"url": url})
        if r.status_code == 429:
            await asyncio.sleep(20)
            r = await client.post(f"{VT}/urls", headers=HEADERS, data={"url": url})
    except httpx.HTTPError:
        return None
    if r.status_code != 200:
        return None
    for _ in range(8):  # wait up to ~1 minute
        await asyncio.sleep(8)
        rep = await vt_get(client, f"/urls/{uid}", retries=0)
        if rep and rep["data"]["attributes"].get("last_analysis_results"):
            return rep["data"]["attributes"]
    return None


async def get_url_attrs(url: str):
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            return await vt_scan_url(client, url)
    except Exception as e:
        print("Link scan error:", repr(e))
        return None


# ---------- report building ----------
def file_name(a: dict, lang: str) -> str:
    names = a.get("names") or []
    return a.get("meaningful_name") or (names[0] if names else tr(lang, "unknown"))


def threat_info(a: dict, bad: int, lang: str) -> dict:
    cls = a.get("popular_threat_classification", {})
    label = cls.get("suggested_threat_label", "unknown")
    cats = [c["value"].lower() for c in cls.get("popular_threat_category", [])]
    families = [n["value"] for n in cls.get("popular_threat_name", [])]
    if not cats and label != "unknown":
        cats = [label.split(".")[0].split("/")[0].lower()]

    worst, best = None, None
    for c in cats:
        info = EXPLAIN.get(c)
        if info and (worst is None
                     or ORDER.index(info["level"]) > ORDER.index(worst)):
            worst, best = info["level"], c
    if worst is None:
        worst = "HIGH" if bad >= 10 else "MEDIUM"

    return {
        "label": label,
        "families": families,
        "cats": cats,
        "type_name": " / ".join(c.upper() for c in cats[:3]) if cats
        else tr(lang, "type_unknown"),
        "level": worst,
        "what": first_sentence(EXPLAIN[best][lang], lang) if best
        else tr(lang, "no_type"),
        "explained": [f"• {c.capitalize()}: {EXPLAIN[c][lang]}"
                      for c in cats if c in EXPLAIN],
    }


def build_short(a: dict, bad: int, sus: int, total: int, ips: list, lang: str) -> str:
    """The short, professional report (Telegram HTML)."""
    e = html.escape
    name = e(short(file_name(a, lang), 40))
    size = round(a.get("size", 0) / 1024, 1)
    flagged = bad + sus

    if flagged == 0:
        return "\n".join([
            f"<b>✅ {tr(lang, 'r_clean')}</b>", LINE,
            f"<b>📄 {tr(lang, 'r_file')}:</b> {name} · {size} KB",
            f"<b>🔎 {tr(lang, 'r_det')}:</b> 0/{total}", "",
            e(tr(lang, "clean_note")), "", tr(lang, "thanks")])

    info = threat_info(a, bad, lang)
    if bad >= ALERT_MIN:
        lvl = LEVEL_NAME[lang][info["level"]]
        head = f"{LEVEL_ICON[info['level']]} {tr(lang, 'r_level', lvl=lvl)}"
    else:
        head = f"🟡 {tr(lang, 'r_sus')}"

    lines = [
        f"<b>{head}</b>", LINE,
        f"<b>🦠 {tr(lang, 'r_type')}:</b> {e(info['type_name'])}",
        f"<b>📄 {tr(lang, 'r_file')}:</b> {name} · {size} KB",
        f"<b>🔎 {tr(lang, 'r_det')}:</b> {flagged}/{total}", "",
        f"<b>💥 {tr(lang, 'r_does')}</b>", e(info["what"]), "",
    ]
    if ips:
        lines.append(f"<b>🌐 {tr(lang, 'r_ip')}:</b>")
        for i in ips[:3]:
            country = i.get("attributes", {}).get("country", "?")
            lines.append(f"<code>{e(defang(i.get('id', '?')))}</code> ({e(str(country))})")
    else:
        lines.append(f"<b>🌐 {tr(lang, 'r_ip')}:</b> {tr(lang, 'r_noip')}")
    lines += [
        "", f"<b>🛡️ {tr(lang, 'r_opened')}</b>", e(tr(lang, "short_opened")),
        "", f"<b>✅ {tr(lang, 'r_tip')}</b>", e(tr(lang, "short_tip")),
        "", tr(lang, "thanks"),
    ]
    return "\n".join(lines)


def build_alert_file(a: dict, bad: int, lang: str, header: str = "") -> str:
    """Very short alarm used by Auto Protection (Telegram HTML)."""
    e = html.escape
    info = threat_info(a, bad, lang)
    lines = []
    if header:
        lines += [f"<b>{e(header)}</b>", ""]
    lines += [
        f"<b>{tr(lang, 'a_file')}</b>",
        f"<b>🦠 {e(info['type_name'])}</b>: {e(info['what'])}",
        tr(lang, "a_do"), "", tr(lang, "thanks"),
    ]
    return "\n".join(lines)


def type_section(a: dict, bad: int, lang: str):
    info = threat_info(a, bad, lang)
    lines = [tr(lang, "type_title", t=info["type_name"]),
             tr(lang, "detected_as", label=info["label"])]
    if info["families"]:
        lines.append(tr(lang, "family", f=", ".join(info["families"][:3])))
    lines.append("\n" + tr(lang, "danger_level", lvl=LEVELS[lang][info["level"]]))
    lines.append("\n" + tr(lang, "what_title"))
    lines.extend(info["explained"] or [tr(lang, "no_type")])
    return "\n".join(lines), info["cats"]


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


def file_info(a: dict, lang: str) -> str:
    votes = a.get("total_votes", {})
    lines = [
        tr(lang, "file_title"),
        f"{tr(lang, 'f_name')}: {short(file_name(a, lang), 60)}",
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
            lines.append(f"• {defang(i.get('id', '?'))} | {at.get('country', '?')} | "
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

    for sandbox, v in list((a.get("sandbox_verdicts") or {}).items())[:3]:
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
                             f"{short(t.get('signature_description', ''), 80)} ({sev})")
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
    return (tr(lang, "det_title") + "\n" + "\n".join(hits[:10])) if hits else ""


def build_full(a: dict, extras: dict, lang: str) -> str:
    """Everything VirusTotal knows (plain text). Shown by the More info button."""
    stats = a.get("last_analysis_stats", {})
    bad = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    total = sum(stats.values())
    flagged = bad + sus

    if flagged == 0:
        verdict = tr(lang, "v_clean", total=total)
    else:
        key = "v_danger" if bad >= 10 else "v_likely" if bad >= 3 else "v_sus"
        verdict = f"{tr(lang, key)}\n{tr(lang, 'flagged_by', n=flagged, total=total)}"

    parts = [tr(lang, "full_title"), verdict]
    if flagged:
        types_text, cats = type_section(a, bad, lang)
        parts += [types_text, advice_section(cats, lang)]
    parts += [file_info(a, lang), network_section(extras, lang),
              behaviour_section(extras, a, lang), detections_section(a, lang),
              tr(lang, "thanks")]
    return "\n\n".join(p for p in parts if p)


def build_link_report(attrs: dict, url: str, lang: str) -> str:
    stats = attrs.get("last_analysis_stats", {})
    bad = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    total = sum(stats.values())
    flagged = bad + sus

    if bad >= ALERT_MIN:
        verdict = tr(lang, "l_danger")
    elif flagged >= 1:
        verdict = tr(lang, "l_sus")
    else:
        verdict = tr(lang, "l_clean")

    lines = [verdict, tr(lang, "l_url", u=short(defang(url), 80))]
    if flagged:
        lines.append(tr(lang, "l_flagged", n=flagged, total=total))
        results = attrs.get("last_analysis_results", {})
        hits = [f"• {eng}: {short(r['result'], 30)}" for eng, r in results.items()
                if r.get("category") in ("malicious", "suspicious")
                and r.get("result")]
        if hits:
            lines.append(tr(lang, "l_det"))
            lines.extend(hits[:3])
        lines.append(tr(lang, "l_advice"))
    else:
        lines.append(tr(lang, "l_clean_note"))
    lines.append(tr(lang, "thanks"))
    return "\n".join(lines)


def extract_urls(message) -> list:
    """Links in a message's text or caption (max 3, http/https only)."""
    found = []
    for e in message.entities or []:
        if e.type == "url":
            found.append(message.parse_entity(e))
        elif e.type == "text_link" and e.url:
            found.append(e.url)
    for e in message.caption_entities or []:
        if e.type == "url":
            found.append(message.parse_caption_entity(e))
        elif e.type == "text_link" and e.url:
            found.append(e.url)
    urls = []
    for u in found:
        if "://" not in u:
            u = "http://" + u
        if u.lower().startswith(("http://", "https://")) and u not in urls:
            urls.append(u)
    return urls[:3]


# ---------- scanning ----------
async def download_and_hash(bot, doc, path: str) -> str:
    tg_file = await bot.get_file(doc.file_id)
    await tg_file.download_to_drive(path)
    return sha256_of(path)


async def scan_link(url: str, lang: str) -> str:
    attrs = await get_url_attrs(url)
    return tr(lang, "l_error") if attrs is None else build_link_report(attrs, url, lang)


async def full_report_for(sha: str, lang: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            report = REPORT_CACHE.get(sha) or await vt_get(client, f"/files/{sha}")
            if not report:
                return tr(lang, "more_missing")
            extras = await fetch_full_extras(client, sha)
    except Exception as e:
        print("Full report error:", repr(e))
        return tr(lang, "error")
    return build_full(report["data"]["attributes"], extras, lang)


async def auto_check_file(bot, doc, store: dict):
    """Quiet background check. Returns the VirusTotal report or None.
    Unknown files are NOT uploaded unless the 'deep' setting is on."""
    if doc.file_size and doc.file_size > MAX_BYTES:
        return None
    sha = UNIQUE_CACHE.get(doc.file_unique_id)
    if sha and sha in REPORT_CACHE:
        return REPORT_CACHE[sha]
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "sample.bin")  # never executed or opened
                sha = await download_and_hash(bot, doc, path)
                cache_put(UNIQUE_CACHE, doc.file_unique_id, sha)
                report, _ = await vt_file_report(
                    client, path, sha, os.path.getsize(path),
                    allow_upload=store.get("deep", False))
    except Exception as e:
        print("Auto scan error:", repr(e))
        return None
    if report:
        cache_put(REPORT_CACHE, sha, report)
    return report


def report_numbers(report: dict):
    a = report["data"]["attributes"]
    st = a.get("last_analysis_stats", {})
    sha = report["data"].get("id") or a.get("sha256")
    return a, st.get("malicious", 0), st.get("suspicious", 0), sum(st.values()), sha


def more_button(lang: str, sha: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton(
        tr(lang, "btn_more"), callback_data="more:" + sha_to_token(sha))]])


# ---------- Telegram handlers ----------
def is_group(update: Update) -> bool:
    chat = update.effective_chat
    return bool(chat and chat.type in ("group", "supergroup"))


def store_for(update: Update, context: ContextTypes.DEFAULT_TYPE) -> dict:
    """Groups keep settings per group; private chats keep them per user."""
    return context.chat_data if is_group(update) else context.user_data


def get_lang(update: Update, context: ContextTypes.DEFAULT_TYPE) -> str:
    return store_for(update, context).get("lang", DEFAULT_LANG)


async def is_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if not is_group(update):
        return True
    user = update.effective_user
    if user is None:
        return False
    try:
        m = await context.bot.get_chat_member(update.effective_chat.id, user.id)
    except Exception:
        return False
    return m.status in ("administrator", "creator")


def lang_keyboard(prefix: str = "lang") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("🇬🇧 English", callback_data=f"{prefix}:en"),
        InlineKeyboardButton("🇰🇭 ខ្មែរ", callback_data=f"{prefix}:km"),
    ]])


def settings_view(store: dict, group: bool = False):
    lang = store.get("lang", DEFAULT_LANG)

    def state(key, default=True):
        return tr(lang, "on" if store.get(key, default) else "off")

    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton(tr(lang, "set_lang_btn"), callback_data="set:lang")],
        [InlineKeyboardButton(f"{tr(lang, 'set_files')}: {state('auto_files')}",
                              callback_data="set:files")],
        [InlineKeyboardButton(f"{tr(lang, 'set_links')}: {state('auto_links')}",
                              callback_data="set:links")],
        [InlineKeyboardButton(f"{tr(lang, 'set_deep')}: {state('deep', False)}",
                              callback_data="set:deep")],
    ])
    return tr(lang, "g_settings_text" if group else "settings_text"), kb


async def ask_language(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if is_group(update):
        await settings_cmd(update, context)
        return
    await update.message.reply_text(S["en"]["choose_lang"],
                                    reply_markup=lang_keyboard())


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    store = store_for(update, context)
    lang = store.get("lang", DEFAULT_LANG)

    args = context.args or []
    if args and args[0].startswith("r_"):  # "More info" link from a group alert
        sha = token_to_sha(args[0][2:])
        if sha:
            await update.message.reply_text(tr(lang, "scanning"))
            await send_long(update.message.reply_text, await full_report_for(sha, lang))
            return

    if is_group(update) or "lang" in store:
        await update.message.reply_text(tr(lang, "welcome"))
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


async def settings_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    store = store_for(update, context)
    if not await is_admin(update, context):
        await update.message.reply_text(tr(store.get("lang", DEFAULT_LANG), "admin_only"))
        return
    text, kb = settings_view(store, is_group(update))
    await update.message.reply_text(text, reply_markup=kb)


async def on_settings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    store = store_for(update, context)
    if not await is_admin(update, context):
        await query.answer(tr(store.get("lang", DEFAULT_LANG), "admin_only"),
                           show_alert=True)
        return
    await query.answer()
    action = query.data.split(":", 1)[1]
    if action == "lang":
        await query.edit_message_text(S["en"]["choose_lang"],
                                      reply_markup=lang_keyboard("setlang"))
        return
    if action == "files":
        store["auto_files"] = not store.get("auto_files", True)
    elif action == "links":
        store["auto_links"] = not store.get("auto_links", True)
    elif action == "deep":
        store["deep"] = not store.get("deep", False)
    text, kb = settings_view(store, is_group(update))
    await query.edit_message_text(text, reply_markup=kb)


async def on_setlang(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    store = store_for(update, context)
    if not await is_admin(update, context):
        await query.answer(tr(store.get("lang", DEFAULT_LANG), "admin_only"),
                           show_alert=True)
        return
    await query.answer()
    lang = query.data.split(":", 1)[1]
    if lang in S:
        store["lang"] = lang
    text, kb = settings_view(store, is_group(update))
    await query.edit_message_text(text, reply_markup=kb)


async def on_more(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """'More info' button: send everything VirusTotal knows about the file."""
    query = update.callback_query
    await query.answer()
    lang = get_lang(update, context)
    sha = token_to_sha(query.data.split(":", 1)[1])
    if not sha:
        return
    await query.message.reply_text(tr(lang, "scanning"))
    await send_long(query.message.reply_text, await full_report_for(sha, lang))


async def hint(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(tr(get_lang(update, context), "hint"))


async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """A person sends a file straight to the bot: full scan with short report."""
    lang = get_lang(update, context)
    doc = update.message.document
    if doc.file_size and doc.file_size > MAX_BYTES:
        await update.message.reply_text(tr(lang, "too_big"))
        return

    await update.message.reply_text(tr(lang, "scanning"))
    report, status, ips = None, "ok", []
    try:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sample.bin")  # never executed or opened
            sha = await download_and_hash(context.bot, doc, path)
            async with httpx.AsyncClient(timeout=60) as client:
                report, status = await vt_file_report(
                    client, path, sha, os.path.getsize(path), allow_upload=True)
                if report:
                    _, bad, sus, _, _ = report_numbers(report)
                    if bad + sus > 0:
                        ips = await fetch_ips(client, sha)
    except Exception as e:
        print("Scan error:", repr(e))
        await update.message.reply_text(tr(lang, "error"))
        return

    if report is None:
        await update.message.reply_text(
            tr(lang, "upload_failed" if status == "upload_failed" else "timeout"))
        return

    cache_put(REPORT_CACHE, sha, report)
    a, bad, sus, total, _ = report_numbers(report)
    await update.message.reply_text(
        build_short(a, bad, sus, total, ips, lang),
        parse_mode="HTML", reply_markup=more_button(lang, sha))


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    lang = get_lang(update, context)
    urls = extract_urls(update.message)
    if not urls:
        await update.message.reply_text(tr(lang, "hint"))
        return
    await update.message.reply_text(tr(lang, "scanning"))
    for u in urls:
        await send_long(update.message.reply_text, await scan_link(u, lang))


# ---------- Auto Protection: groups ----------
async def on_group_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Quietly check files and links in a group. Speak up only if dangerous."""
    msg = update.effective_message
    if msg is None or (msg.from_user and msg.from_user.is_bot):
        return
    cd = context.chat_data
    lang = cd.get("lang", DEFAULT_LANG)

    try:
        if msg.document and cd.get("auto_files", True):
            report = await auto_check_file(context.bot, msg.document, cd)
            if report:
                a, bad, _, _, sha = report_numbers(report)
                if bad >= ALERT_MIN:
                    link = f"https://t.me/{context.bot.username}?start=r_{sha_to_token(sha)}"
                    kb = InlineKeyboardMarkup([[InlineKeyboardButton(
                        tr(lang, "btn_more"), url=link)]])
                    await msg.reply_text(build_alert_file(a, bad, lang),
                                         parse_mode="HTML", reply_markup=kb)

        if cd.get("auto_links", True):
            for u in extract_urls(msg):
                attrs = await get_url_attrs(u)
                if attrs and attrs.get("last_analysis_stats", {}).get(
                        "malicious", 0) >= ALERT_MIN:
                    await msg.reply_text(build_link_report(attrs, u, lang))
    except Exception as e:
        print("Group handler error:", repr(e))


# ---------- Auto Protection: Telegram Business chats ----------
async def get_connection(context: ContextTypes.DEFAULT_TYPE, bc_id: str) -> dict:
    cache = context.bot_data.setdefault("bc", {})
    if bc_id not in cache:
        conn = await context.bot.get_business_connection(bc_id)
        cache[bc_id] = {"owner_id": conn.user.id, "chat_id": conn.user_chat_id}
    return cache[bc_id]


async def tell_owner(context, chat_id: int, text: str, kb=None, html_mode=False):
    try:
        await context.bot.send_message(
            chat_id=chat_id, text=text,
            parse_mode="HTML" if html_mode else None, reply_markup=kb)
    except Exception as e:
        print("Could not message owner:", repr(e))


async def on_business_connection(conn, context: ContextTypes.DEFAULT_TYPE):
    cache = context.bot_data.setdefault("bc", {})
    lang = context.application.user_data[conn.user.id].get("lang", DEFAULT_LANG)
    if conn.is_enabled:
        cache[conn.id] = {"owner_id": conn.user.id, "chat_id": conn.user_chat_id}
        text = tr(lang, "b_connected")
    else:
        cache.pop(conn.id, None)
        text = tr(lang, "b_disconnected")
    await tell_owner(context, conn.user_chat_id, text)


async def on_business_update(update: Update, context: ContextTypes.DEFAULT_TYPE):
    conn = getattr(update, "business_connection", None)
    if conn is not None:
        await on_business_connection(conn, context)
        return

    msg = getattr(update, "business_message", None)
    if msg is None:
        return
    try:
        info = await get_connection(context, msg.business_connection_id)
    except Exception as e:
        print("Business connection error:", repr(e))
        return

    sender = msg.from_user
    # Ignore the owner's own outgoing messages and bots.
    if sender is None or sender.is_bot or sender.id == info["owner_id"]:
        return

    ud = context.application.user_data[info["owner_id"]]
    lang = ud.get("lang", DEFAULT_LANG)
    who = sender.full_name + (f" (@{sender.username})" if sender.username else "")
    header = tr(lang, "b_from", who=who)

    # Only files and links are checked. Plain text and photos are ignored.
    # Safe items stay silent; only dangerous ones are reported, privately to you.
    if msg.document and ud.get("auto_files", True):
        report = await auto_check_file(context.bot, msg.document, ud)
        if report:
            a, bad, _, _, sha = report_numbers(report)
            if bad >= ALERT_MIN:
                await tell_owner(context, info["chat_id"],
                                 build_alert_file(a, bad, lang, header),
                                 kb=more_button(lang, sha), html_mode=True)

    if ud.get("auto_links", True):
        for u in extract_urls(msg):
            attrs = await get_url_attrs(u)
            if attrs and attrs.get("last_analysis_stats", {}).get(
                    "malicious", 0) >= ALERT_MIN:
                await tell_owner(context, info["chat_id"],
                                 f"{header}\n\n{build_link_report(attrs, u, lang)}")


def main():
    # PicklePersistence remembers each user's and group's settings between
    # restarts (it resets if the host wipes its disk on redeploy).
    persistence = PicklePersistence(filepath="bot_data.pkl")
    builder = (ApplicationBuilder().token(TELEGRAM_TOKEN)
               .persistence(persistence)
               .concurrent_updates(True))  # a slow scan must not block others
    if BOT_API_URL:  # self-hosted Bot API server => files bigger than 20 MB
        builder = (builder.base_url(f"{BOT_API_URL}/bot")
                   .base_file_url(f"{BOT_API_URL}/file/bot")
                   .local_mode(True))
    app = builder.build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", start))
    app.add_handler(CommandHandler("language", ask_language))
    app.add_handler(CommandHandler("settings", settings_cmd))
    app.add_handler(CallbackQueryHandler(on_language, pattern=r"^lang:"))
    app.add_handler(CallbackQueryHandler(on_settings, pattern=r"^set:"))
    app.add_handler(CallbackQueryHandler(on_setlang, pattern=r"^setlang:"))
    app.add_handler(CallbackQueryHandler(on_more, pattern=r"^more:"))

    private = filters.ChatType.PRIVATE & filters.UpdateType.MESSAGE
    app.add_handler(MessageHandler(filters.Document.ALL & private, handle_file))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND & private,
                                   handle_text))
    app.add_handler(MessageHandler(
        (filters.PHOTO | filters.VIDEO | filters.AUDIO) & private, hint))
    app.add_handler(MessageHandler(
        filters.ChatType.GROUPS & ~filters.COMMAND & filters.UpdateType.MESSAGE,
        on_group_message))
    # Business updates (chats you connected) are handled here.
    app.add_handler(TypeHandler(Update, on_business_update), group=1)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()