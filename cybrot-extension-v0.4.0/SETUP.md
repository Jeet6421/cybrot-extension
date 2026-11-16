# CYBROT setup guide

CYBROT has two parts:

1. **The browser extension.** This is the popup you click on any website.
2. **The CYBROT engine.** This is a Python program that runs on your own computer. The extension sends scan requests to it.

The extension does nothing until the engine is running. If the popup shows **Engine offline**, follow the steps below.

---

## Before you start

You need:

- **Python 3.8 or newer.** Check with the commands below.
- **Chrome or Microsoft Edge.**
- **The CYBROT engine files.** [ADD DOWNLOAD LINK OR INSTRUCTIONS FOR THE ENGINE HERE]

Check Python:

| System | Command |
| --- | --- |
| Windows | `py --version` |
| Mac | `python3 --version` |
| Linux | `python3 --version` |

If Python is missing:

- **Windows:** install it from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
- **Mac:** install it from https://www.python.org/downloads/macos/.
- **Linux:** run `sudo apt install python3` (Ubuntu and Debian) or use your distribution's package manager.

---

## Step 1: Load the extension

1. Unzip `cybrot-extension-v0.1.0.zip` into a folder you can find again, such as your Desktop or Documents.
2. Open the extensions page:
   - Chrome: type `chrome://extensions` in the address bar.
   - Edge: type `edge://extensions` in the address bar.
3. Turn on **Developer mode**.
4. Click **Load unpacked** and select the unzipped folder, the one that contains `manifest.json`.
5. Pin the CYBROT icon to the toolbar.

---

## Step 2: Start the engine

Open a terminal in the unzipped folder.

**Windows (PowerShell or Command Prompt):**

```powershell
py dev\engine_stub.py
```

**Mac and Linux (Terminal):**

```bash
python3 dev/engine_stub.py
```

> The `engine_stub.py` file is a test engine. It returns sample data, not real scan results. Replace this command with the start command for the real CYBROT engine once it's available: [ADD REAL ENGINE START COMMAND HERE]

When it's running, you'll see:

```
CYBROT engine stub on http://127.0.0.1:8000 (sample data only)
```

Leave this terminal open while you use the extension. Closing it stops the engine.

---

## Step 3: Check the connection

1. Click the CYBROT icon in the browser.
2. The status at the top should say **Engine online**.
3. If it still says **Engine offline**, click the status to check again.

To test the engine directly, open http://127.0.0.1:8000/api/health in your browser. You should see `{"status": "ok", ...}`.

---

## Step 4: Run a scan

1. Open a website, for example `https://example.com`.
2. Click the CYBROT icon. The domain appears in the popup.
3. Choose the scan modules and click **Start scan**.
4. Wait for the results to appear.

---

## Troubleshooting

| Problem | What to do |
| --- | --- |
| **Engine offline** | Start the engine (Step 2). Keep its terminal window open. |
| `can't open file` or `No such file` in the terminal | Check that you're in the unzipped folder. Run `dir` (Windows) or `ls` (Mac/Linux) and confirm you can see a `dev` folder. |
| `python` or `py` not found | Python isn't installed or isn't on your PATH. See Before you start. |
| Port 8000 already in use | Another program is using port 8000. Close it, or restart your computer. |
| Popup says "Can't scan this page" | Open a normal website (http or https). Browser pages such as `chrome://` pages can't be scanned. |

If none of these fix the problem, send the exact error message and the step where it happens.
