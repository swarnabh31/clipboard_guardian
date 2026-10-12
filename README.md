# 🛡️ Clipboard Guardian

**A seatbelt for your clipboard.** Install once, forget it. It sits in your system tray and checks every piece of text you copy, instantly and privately.

- 🔑 Copied a password, API key, access token, recovery phrase or one-time code? It warns you and **auto-wipes the clipboard after 30 seconds**.
- 🪪 Copied an ID, card or bank number or a home address? Same protection.
- ⚡ **60+ well-known key formats** (AWS, Google, GitHub, GitLab, Hugging Face, OpenAI, Anthropic, Stripe, Slack, Discord, npm, PyPI and many more), private keys, JWTs, database URLs with passwords, bearer tokens and valid card numbers are caught instantly by built-in patterns, even if Ollama is down.
- 🧬 **Formats nobody has written a rule for** are still caught when they look like a randomly generated key.
- 🔐 **Passwords**: labelled ones (`password: ...`, `my password is ...`), complex-looking ones (`Tr0ub4dor&3`, `gh456M_`) and anything copied from a password manager.
- 🎣 Copied a scam or phishing message? You get a warning before you click or paste it anywhere.
- 🧩 **Teach it new formats** without touching the code (see [Custom rules](#custom-rules-and-learning)).
- 🔒 **100% local**: the language model is [Nimble](https://ollama.com/library/nimble), a 9B decision model running on Ollama. Nothing is logged or sent anywhere.
- 💸 **Free**, no accounts, no API keys.

## Quickstart (Windows)

1. Install [Ollama 0.35+](https://ollama.com/download).
2. Open a terminal (activate your Python environment if you use one) and double-click or run `run.bat`.

It installs the dependencies, pulls `nimble`, and starts the tray app with no console window. Right-click the green tray icon and tick **Start with Windows** to make it permanent.

Manual run: `pip install -r requirements.txt` then `python guardian.py`.

Requirements are unchanged: `pystray`, `pyperclip`, `pillow` and `requests`.

## How a copy is checked

Every copy goes through these layers in order and stops at the first match. The first four are plain code and never need Ollama.

1. **Known formats**: 60+ named patterns (cloud, code hosting, AI services, payments, messaging, monitoring, keys and wallets), card numbers (with a checksum), `KEY=value` assignments and credentials embedded in URLs or headers.
2. **Your custom rules**: anything you added to `custom_rules.txt`.
3. **Passwords**:
   - labelled values such as `password: hunter2` or `DB_PASSWORD=...`, even short ones
   - unlabelled, complex-looking strings: a single token of 6 to 40 characters with a lowercase letter, an uppercase letter, a digit and a symbol (`!@#$%^&*+?~|`), or exactly one `_` or `-` in a short, word-free string such as `gh456M_`
   - copies tagged by a password manager (Windows only, see notes)
4. **Random-looking tokens**: a single string of 24 to 128 characters that mixes upper case, lower case and digits like a generated key. Identifiers, file names, URLs, paths, hashes and UUIDs are excluded.
5. **The model**: everything else (8 to 4,000 characters) is judged by `nimble` for secrets, personal or financial data, and scams.

## Tray menu

- **Paused**: stop checking temporarily
- **Wipe sensitive copies**: on by default; untick it to get a warning only (useful when you are deliberately sharing a password or key)
- **Detection rules**
  - **Detect unknown token formats**: the random-looking-token layer
  - **Detect password-like text**: the unlabelled-password layer
  - **Flag password-manager copies**: treat anything your password manager copies as sensitive
  - **Learn format from last copy**: turn the key you just copied into a permanent rule
  - **Edit custom rules...**: opens `custom_rules.txt`
- **Decision model**: pick from your installed Ollama models (keep it on `nimble`; other models must support Ollama's decision API)
- **Start with Windows**: launch automatically at login
- **Quit**

## Custom rules and learning

Providers invent new key formats all the time. Two ways to handle that without editing the code:

**Learn from last copy** (easiest). When a key slips through, copy it again, right-click the tray icon and choose **Detection rules → Learn format from last copy**. The app writes a rule for the format (its prefix, character set and length) into `custom_rules.txt`, and every key of that format is caught from then on. Only the format is stored, never the key itself.

**Edit the file.** `custom_rules.txt` sits next to `guardian.py`. One rule per line: `Name | regular expression`. Lines starting with `#` are ignored. It reloads automatically when you save it, so there is no need to restart.

```
# Acme internal key | \bacme_[A-Za-z0-9]{32}\b
```

Invalid lines are skipped (run with `--debug` to see which).

## Troubleshooting

Quit any running copy from the tray, then run `python guardian.py --debug` in a terminal and copy some text. It prints each step (clipboard change seen, which built-in rule matched, model scores, decision) and never prints the copied text. A quick check: copy `AKIAIOSFODNN7EXAMPLE`; you should see `built-in rule matched: AWS access key id`.

- **No `clipboard changed` line:** the Windows clipboard hook isn't working.
- **A rule matched but there is no popup:** Windows Focus Assist or your notification settings are hiding it.
- **`model call failed`:** check that Ollama is running (`ollama list`) and that the model supports the decision API. The built-in layers keep working without it.
- **Nothing matched:** the text fell through every layer; use **Learn format from last copy** or add a custom rule.
- **Password-manager copies not flagged:** copy a password from your manager with `--debug` on. If `Copied from a password manager` never appears, your manager doesn't set the marker this app looks for. Passwords from it are still caught if they look like a complex password.

## Honest notes

- **What was tested:** the built-in detection (key formats, passwords, random-looking tokens, custom rules, back-to-back copies) was run against sample data, including a set of ordinary text, code, file names and hashes that must *not* trigger. The Windows parts (tray menu, clipboard hook, notifications, password-manager check) and the call to Ollama could not be run in that setup. Please open an issue if something breaks.
- **Random keys:** the unknown-format layer catches roughly 90% of random keys of 32 characters or more, and fewer of the shortest ones (about 75% at 24 characters).
- **Hex keys and hashes:** a bare 32, 40 or 64 character hex string looks exactly like a file checksum or git commit ID, so it is deliberately ignored unless it has a prefix you taught the app.
- **Passwords without a label or a symbol** (`Summer2024`, `hunter2`) and word-based passphrases look like ordinary text, so only the model can try to judge them, and its probabilities are not calibrated. Expect occasional misses and false alarms; it is a safety net, not a guarantee.
- **False alarms:** short codes that look like complex passwords (`Ab12!Cd34`, `my_Var2`) are sometimes flagged. Untick **Detect password-like text** if that bothers you.
- **Password managers** often clear the clipboard themselves. This app adds a warning and a wipe on top, which means a notification each time you copy a login. Untick **Flag password-manager copies** or **Wipe sensitive copies** if that is too noisy. Which managers set the marker this app looks for varies by app.
- Built-in layers check text between 6 and 4,000 characters. Only text of 8 characters or more goes to the model, and only the clipboard text is ever sent to your local Ollama.
- It waits for Windows' clipboard-change notification instead of polling, so it is idle until you copy something. If that hook can't start, it quietly falls back to checking every half second.
- Slow model calls run in the background, so copying several keys in a row is handled. A copy made within a few milliseconds of another may only be seen once.
- The app cannot tell where you are pasting. If you intentionally share something sensitive, paste it within 30 seconds or switch off **Wipe sensitive copies**.
- Clipboard wiping only works if the clipboard still holds the same text after 30 seconds. Copying the same text twice in a row is checked only once.
- Notifications use the tray icon's built-in pop-ups, so Windows Focus Assist may hide them.

## License

MIT — see the [`LICENSE`](LICENSE) file.
