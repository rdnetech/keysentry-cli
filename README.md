# KeySentry CLI

Vault credentials, scan for exposed keys, and sign in to the KeySentry Gateway from your terminal.

## Install

```bash
npm install -g @keysentry/cli
```

## Quick Start

```bash
# Authenticate
keysentry login

# Vault a credential (interactive)
keysentry vault

# Vault with flags
keysentry vault --key="sk-ant-..." --name="prod-anthropic" --env=production --rotate=90

# Pipe from environment
echo $OPENAI_API_KEY | keysentry vault --name="openai-prod"

# Scan text for exposed credentials
cat .env | keysentry scan

# Scan clipboard (macOS)
pbpaste | keysentry scan
```

## Commands

| Command | Description |
|---------|-------------|
| `login` | Authenticate with your KeySentry API key |
| `vault` | Save a credential to your encrypted vault |
| `scan` | Scan text for exposed credentials (30 patterns) |
| `status` | Show connection status |
| `token` | Print a short-lived Gateway sign-in token (Claude Code `apiKeyHelper`) |
| `help` | Show help |

## Gateway sign-in for Claude Code (`keysentry token`)

Developers sign in once with their work Microsoft account. After that,
`keysentry token` prints a short-lived Microsoft Entra ID token that the
KeySentry Gateway accepts, renewing it quietly in the background. No shared
API key is handed out.

Your IT team deploys this in Claude Code managed settings:

```json
{
  "env": { "ANTHROPIC_BASE_URL": "https://gateway.getkeysentry.com" },
  "apiKeyHelper": "keysentry token --tenant <tenant-id> --client <client-id>"
}
```

`<tenant-id>` and `<client-id>` are the Directory (tenant) ID and the
Application (client) ID on the Overview page of your company's Entra app.

First run: sign in once in a terminal before starting Claude Code. Claude
Code does not wait for a browser sign-in, so when no sign-in is saved the
helper stops right away and tells you this command:

```bash
keysentry token --tenant <tenant-id> --client <client-id> --info
```

| Option | What it does |
|--------|--------------|
| `--tenant <id>` | Directory (tenant) ID (required) |
| `--client <id>` | Application (client) ID (required) |
| `--info` | Shows who is signed in and how long the token lasts; prints no token |
| `--logout` | Removes the saved sign-in from this computer |

Where the sign-in is kept: the macOS Keychain on a Mac; elsewhere
`~/.keysentry/sso/`, readable only by you. The command prints nothing but the
token on standard output; messages go to standard error.

## GitHub Copilot through the Gateway (`keysentry copilot-key`)

GitHub Copilot (VS Code chat with a Custom Endpoint, and Copilot CLI) can't sign in with Microsoft on every
request, so each person gets a personal Gateway key instead. Requests are still logged, budgeted and checked
under their name, and turning them off in KeySentry stops the key.

```bash
keysentry copilot-key --tenant <tenant-id> --client <client-id>
```

Signs you in if needed, gets your key, saves it on this computer and copies it to the clipboard for VS Code.
If you already have a key, the new one waits for an administrator's approval and your current key keeps
working until then. Keys last 90 days.

Copilot CLI reads the saved key:

```bash
export COPILOT_PROVIDER_API_KEY="$(keysentry copilot-key --tenant <tenant-id> --client <client-id> --print)"
```

| Option | What it does |
|--------|--------------|
| `--print` | Prints the saved key only (nothing else on standard output) |
| `--forget` | Removes the saved key from this computer |

Inline code completions in Copilot stay on GitHub's service; chat and agent requests go through the Gateway.

## Auto-Detection

Paste any credential and KeySentry automatically detects the platform, type, and suggests rotation:

- OpenAI (`sk-proj-`, `sk-`)
- Anthropic (`sk-ant-`)
- Google AI (`AIza`)
- AWS (`AKIA`)
- GitHub (`ghp_`, `gho_`, `ghs_`)
- Grok/xAI (`xai-`)
- Slack (`xoxb-`, `xoxp-`)
- Stripe (`sk_live_`, `sk_test_`)
- And 20+ more patterns
