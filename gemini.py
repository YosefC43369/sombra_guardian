"""
gemini.py — Google Gemini API integration for the Telegram moderation bot.

Responsibilities (and only these):
  - Read GEMINI_API_KEY / GEMINI_MODEL from the environment at call time
    (never hardcoded, never read at import time — see note below).
  - Validate user input before it is sent to Gemini (empty / too long).
  - Call the Gemini API asynchronously so the bot's event loop is never
    blocked while waiting for a response.
  - Translate every failure mode (missing/invalid key, quota, rate limit,
    timeout, network error, empty response, unexpected exception) into a
    safe, Thai, user-facing message. Never raises out to bot.py and never
    leaks the API key or a stack trace to a Telegram user.
  - Split long Gemini responses into Telegram-safe chunks (<=4096 chars).

Environment variables are read lazily (inside functions, not at module
import time): bot.py calls load_dotenv() AFTER its own import block, so
reading os.environ at import time here would run before .env is loaded
during local development.

gemini.py never talks to Telegram directly and never touches the SQLite
database — that stays in bot.py / security.py, matching the separation
of concerns already used by detection.py.
"""