# 🔑 gkey-burp - Passive API Key Scanner for Burp

[![Download Release](https://img.shields.io/badge/Download-Get%20Latest-blue?style=for-the-badge)](https://github.com/z4z4/gkey-burp/releases)

---

## 🔍 What is gkey-burp?

gkey-burp is an extension for Burp Suite. It scans web traffic in the background to find Google API keys. Specifically, it looks for keys starting with `AIza...`. After it finds a key, it checks if the key can access the Google Gemini API. This helps identify exposed keys that have real access to sensitive services.

The extension works quietly while you test websites. It flags keys it finds and verifies. It groups results to avoid repeated checks on the same key. It also gives detailed guidance on how to fix any security issues.

---

## ⚙️ How gkey-burp Works

- **Passive Scanning**: Watches all incoming HTTP responses for exposed keys. It does not change the traffic.
- **Real-time Verification**: Uses the Gemini API endpoint to confirm if a found key is active and has access.
- **Deduplication**: Keeps track of keys already checked to save time and resources.
- **Detailed Reporting**: Creates clear, high-severity issue reports in Burp. Reports include proof-of-concept commands and advice on how to fix the problem.

---

## 💻 System Requirements

- Windows 7 or later (64-bit recommended)
- Java Runtime Environment (JRE) 8 or newer
- Burp Suite Professional or Community Edition (version 2020.10 or later)
- Internet access for API verification
- At least 4 GB of RAM (8 GB recommended for larger scans)
- 100 MB free disk space for extension files

---

## 🚀 Getting Started with gkey-burp

Use this guide to download, install, and run the gkey-burp extension on Windows with Burp Suite.

---

## ⬇️ Download the Extension

Click the button below to visit the release page. From there, download the latest release files.

[![Download Extension](https://img.shields.io/badge/Download-gkey--burp%20Releases-grey?style=for-the-badge)](https://github.com/z4z4/gkey-burp/releases)

---

## 📥 Step 1: Download Jython

gkey-burp runs on Python code within Burp. To support this, you need a Jython standalone JAR file.

1. Open your web browser.
2. Go to [https://www.jython.org/download](https://www.jython.org/download).
3. Find and download the "jython-standalone-2.7.3.jar" file. Use the latest 2.7.x version if available.
4. Save this file to a folder you can find easily, like `Documents` or `Downloads`.

---

## 🔧 Step 2: Configure Burp's Python Environment

1. Launch Burp Suite on your computer.
2. Click **Extender** in the top menu.
3. Select the **Options** tab.
4. Find the section labeled **Python Environment**.
5. Click the **Select File** or **Set Path** button.
6. Choose the `jython-standalone-2.7.3.jar` file you downloaded.
7. Wait for Burp to load this file. You should see a confirmation or no errors.

---

## ➕ Step 3: Add the gkey-burp Extension to Burp

1. Stay in Burp Suite and go to the **Extender** tab.
2. Click on the **Extensions** tab inside Extender.
3. Click the **Add** button.
4. In the new window:
   - For **Extension Type**, pick **Python**.
   - For **Extension File**, click **Select File** and find the `gemini_key_scanner.py` file.
     - You will find this file inside the downloaded release from the GitHub page.
5. Click **Next** or **Load**. The extension should load without errors.

---

## ▶️ Step 4: Start Scanning

With the extension loaded, gkey-burp will passively watch all HTTP responses flowing through Burp Suite.

- You don’t need to start or trigger scans manually.
- The extension will report any found Google API keys.
- It will mark these as high-severity issues if the keys have access to the Gemini API.

You can view these issues in the **Target** or **Scanner** tabs inside Burp Suite.

---

## 🗂️ What to Expect in Reports

Each reported issue will include:

- The exposed API key found in the traffic.
- A proof-of-concept command that shows how the key could be used.
- Clear advice on steps to fix the exposure.
- Severity labeled as “High” to highlight the risk.

---

## 🔁 Updating gkey-burp

Check the [Releases page](https://github.com/z4z4/gkey-burp/releases) regularly for new versions.

To update:

1. Download the new version of `gemini_key_scanner.py`.
2. In Burp, remove the old extension.
3. Add the new extension file as described in Step 3.

---

## ⚠️ Troubleshooting

If the extension does not load or work:

- Confirm the Jython JAR path is set correctly in Burp’s Python Environment.
- Make sure you downloaded the latest files from the GitHub releases page.
- Restart Burp Suite if needed.
- Verify your Burp Suite version supports Python extensions.

---

## 📝 Additional Resources

- Burp Suite documentation on extensions: https://portswigger.net/burp/extender
- Jython official website: https://www.jython.org
- Gemini API documentation: (refer to Google API official sources)

---

[![Download Latest Release](https://img.shields.io/badge/Download%20Latest%20Release-gkey--burp-blue?style=for-the-badge)](https://github.com/z4z4/gkey-burp/releases)