# windows-error-assistant
AI-powered Windows error assistant with notifications and multi-provider support (ChatGPT, Grok, Copilot, Gemini)
# 🚨 Windows Error Assistant (Beta)

AI-powered Windows error assistant — whenever a Windows error popup appears,  
it shows a **notification** with quick actions:  
- 🔍 Search the web  
- 🤖 Ask an AI (ChatGPT, Grok, Copilot, Gemini)  
- 📝 View local log  

---

## ✨ Features
- Monitor **Windows Event Logs** (System, Application, Security)  
- Detect **UI error popups** (e.g., *Location is not available*)  
- Show actionable **notifications** with buttons  
- Connect to **multiple AI providers** (ChatGPT, Grok, Copilot, Gemini)  
- Manage **API keys securely** with DPAPI  
- Configuration through **PySide6 GUI**  
- **Redaction**: remove sensitive paths or data before sending to AI  
- **Rate limiting** and message length restrictions  

---

## ⚠️ Privacy Notice
- Error messages may include local paths or sensitive data.  
- If `allow_send_to_ai` is enabled in `config.json`, these messages are sent to external providers (e.g., OpenAI).  
- Default is **off**.  
- You can enable or disable this via the GUI or by editing the config.  

---

## 📦 Installation

Requires: **Python 3.10+**

```bash
git clone https://github.com/<username>/python mi.py
windows-error-assistant{
  "ai_provider": "openai",
  "openai": { "api_key": "sk-xxxx", "model": "gpt-3.5-turbo" },
  "server": { "host": "127.0.0.1", "port": 5000, "allow_remote_bind": false, "confirm_remote": false },
  "allow_send_to_ai": false,
  "redact_before_send": true,
  "store_raw_logs": false,
  "ai_limits": { "max_message_chars": 4000, "min_interval_seconds": 2 },
  "monitor": { "event_poll_interval": 30, "ui_poll_interval": 1, "time_window_hours": 24, "max_errors": 10 }
}
.git
cd windows-error-assistant
pip install -r requirements.txt
