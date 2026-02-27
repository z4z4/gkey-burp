# Burp Suite Extension: Gemini API Key Scanner

A passive scanner extension for Burp Suite that detects exposed Google API keys (`AIza...`) and verifies if they have access to the Google Gemini API.

## Features

- **Passive Scanning**: Automatically scans all HTTP responses passing through Burp
- **Real-time Verification**: Calls the Gemini models endpoint to confirm API access
- **Deduplication**: Tracks verified keys to avoid redundant API calls
- **Detailed Reporting**: Creates High severity issues with PoC commands and remediation guidance

## Installation

### 1. Install Jython

1. Download Jython standalone JAR from [jython.org/download](https://www.jython.org/download)
   - Get `jython-standalone-2.7.3.jar` (or latest 2.7.x)
2. In Burp Suite, go to **Extender > Options > Python Environment**
3. Set the path to your downloaded `jython-standalone-2.7.x.jar`

### 2. Load the Extension

1. Go to **Extender > Extensions > Add**
2. Extension Type: **Python**
3. Extension file: Select `gemini_key_scanner.py`
4. Click **Next**

You should see in the Output tab:
```
[+] Gemini API Key Scanner loaded successfully
[+] Passively scanning for Google API keys with Gemini access
```

## Usage

Once loaded, the extension works automatically:

1. Browse target websites through Burp proxy
2. The extension scans all responses for `AIza` prefixed keys
3. Found keys are verified against the Gemini API
4. If a key has Gemini access, a **High** severity issue is created

### Viewing Results

- Go to **Target > Site map** or **Dashboard > Issue activity**
- Look for issues named **"Exposed Google API Key with Gemini Access"**
- Each issue includes:
  - The full API key
  - Available Gemini models
  - Proof of concept curl commands
  - Remediation guidance

## Issue Details

When a vulnerable key is found, the extension reports:

| Field | Value |
|-------|-------|
| Severity | High |
| Confidence | Certain |
| Issue Name | Exposed Google API Key with Gemini Access |

The issue detail includes:
- The exposed API key
- List of accessible Gemini models
- PoC commands to verify and exploit
- Links to Truffle Security research

## How It Works

```
Response received
       │
       ▼
┌─────────────────┐
│ Regex search    │
│ for AIza keys   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Key already     │──Yes──► Skip (already reported)
│ verified?       │
└────────┬────────┘
         │ No
         ▼
┌─────────────────┐
│ Call Gemini     │
│ /v1beta/models  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ HTTP 200?       │──No───► Log and skip
└────────┬────────┘
         │ Yes
         ▼
┌─────────────────┐
│ Create High     │
│ severity issue  │
└─────────────────┘
```

## Limitations

- Only performs passive scanning (doesn't inject payloads)
- Requires internet access to verify keys against Google's API
- Keys restricted by IP/referrer may show as "no access" even if valid

## References

- [Truffle Security Research: Google API Keys Weren't Secrets](https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules)
- [Google Cloud API Key Best Practices](https://cloud.google.com/docs/authentication/api-keys)

## License

MIT - Use responsibly for authorized security testing only.
