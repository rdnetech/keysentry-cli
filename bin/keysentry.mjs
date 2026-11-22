#!/usr/bin/env node
import { createInterface } from "readline";
import { homedir } from "os";
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from "fs";
import { join } from "path";
import { tokenCommand } from "../lib/sso.mjs";

// Version comes from package.json, so a release only bumps it in one place.
const VERSION = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
const API_BASE = "https://www.getkeysentry.com";
const CONFIG_DIR = join(homedir(), ".keysentry");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");

// ═══ CREDENTIAL PATTERNS ═══
const PATTERNS = [
  { prefix: "sk-ant-", platform: "anthropic", type: "api_key", label: "Anthropic API Key", rotation: 90 },
  { prefix: "sk-proj-", platform: "openai", type: "api_key", label: "OpenAI Project Key", rotation: 90 },
  { prefix: "sk-svcacct-", platform: "openai", type: "service_account", label: "OpenAI Service Account", rotation: 60 },
  { prefix: "sk-", platform: "openai", type: "api_key", label: "OpenAI API Key", rotation: 90 },
  { prefix: "AIza", platform: "google", type: "api_key", label: "Google AI API Key", rotation: 180 },
  { prefix: "AKIA", platform: "aws", type: "api_key", label: "AWS Access Key", rotation: 90 },
  { prefix: "ghp_", platform: "github", type: "pat", label: "GitHub PAT", rotation: 60 },
  { prefix: "gho_", platform: "github", type: "oauth", label: "GitHub OAuth Token", rotation: 90 },
  { prefix: "ghs_", platform: "github", type: "server_token", label: "GitHub Server Token", rotation: 30 },
  { prefix: "github_pat_", platform: "github", type: "pat", label: "GitHub Fine-Grained PAT", rotation: 60 },
  { prefix: "xai-", platform: "xai", type: "api_key", label: "Grok / xAI API Key", rotation: 90 },
  { prefix: "xoxb-", platform: "slack", type: "bot_token", label: "Slack Bot Token", rotation: 365 },
  { prefix: "xoxp-", platform: "slack", type: "user_token", label: "Slack User Token", rotation: 365 },
  { prefix: "glpat-", platform: "gitlab", type: "pat", label: "GitLab PAT", rotation: 60 },
  { prefix: "ATATT", platform: "atlassian", type: "api_key", label: "Atlassian API Token", rotation: 180 },
  { prefix: "sk_live_", platform: "stripe", type: "api_key", label: "Stripe Live Key", rotation: 365 },
  { prefix: "sk_test_", platform: "stripe", type: "api_key", label: "Stripe Test Key", rotation: 365 },
  { prefix: "SG.", platform: "sendgrid", type: "api_key", label: "SendGrid API Key", rotation: 180 },
  { prefix: "re_", platform: "resend", type: "api_key", label: "Resend API Key", rotation: 180 },
  { prefix: "hf_", platform: "huggingface", type: "api_key", label: "Hugging Face Token", rotation: 180 },
  { prefix: "r8_", platform: "replicate", type: "api_key", label: "Replicate API Token", rotation: 180 },
  { prefix: "npm_", platform: "npm", type: "api_key", label: "NPM Access Token", rotation: 90 },
  { prefix: "pypi-", platform: "pypi", type: "api_key", label: "PyPI API Token", rotation: 90 },
  { prefix: "dop_v1_", platform: "digitalocean", type: "pat", label: "DigitalOcean PAT", rotation: 90 },
];

function detect(key) {
  const sorted = [...PATTERNS].sort((a, b) => b.prefix.length - a.prefix.length);
  for (const p of sorted) {
    if (key.startsWith(p.prefix)) return p;
  }
  if (/^[A-Za-z0-9_-]{32,}$/.test(key)) {
    return { prefix: "", platform: "unknown", type: "api_key", label: "API Key (unknown)", rotation: 90 };
  }
  return null;
}

// ═══ CONFIG ═══
function loadConfig() {
  try {
    if (existsSync(CONFIG_FILE)) return JSON.parse(readFileSync(CONFIG_FILE, "utf-8"));
  } catch {}
  return {};
}

function saveConfig(config) {
  if (!existsSync(CONFIG_DIR)) mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  // The config holds the org API key: readable by this user only.
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
  chmodSync(CONFIG_FILE, 0o600);
}

// ═══ READLINE HELPER ═══
function ask(question) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer.trim()); }));
}

// ═══ COLORS ═══
const c = {
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  purple: (s) => `\x1b[35m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
};

// ═══ COMMANDS ═══
async function login() {
  console.log("\n" + c.purple("  KeySentry AI") + " — CLI Authentication\n");
  const apiKey = await ask("  API Key (from Settings > API): ");
  if (!apiKey) { console.log(c.red("  ✗ No API key provided")); process.exit(1); }
  
  // Verify the key
  try {
    const res = await fetch(`${API_BASE}/api/cli/auth`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apiKey }),
    });
    if (res.ok) {
      const data = await res.json();
      saveConfig({ apiKey, email: data.email });
      console.log(c.green("  ✓ Authenticated as " + (data.email || "unknown")));
      console.log(c.dim("  Config saved to ~/.keysentry/config.json\n"));
    } else {
      console.log(c.red("  ✗ Invalid API key"));
      process.exit(1);
    }
  } catch (err) {
    // For now, save the key and trust it
    saveConfig({ apiKey });
    console.log(c.yellow("  ⚠ Could not verify (offline mode). Key saved.\n"));
  }
}

async function vault(args) {
  const config = loadConfig();
  if (!config.apiKey) {
    console.log(c.red("  ✗ Not authenticated. Run: keysentry login\n"));
    process.exit(1);
  }

  const isPiped = !process.stdin.isTTY;
  console.log("\n" + c.purple("  KeySentry AI") + " — Vault Credential\n");

  // Parse flags
  let key = args.find(a => a.startsWith("--key="))?.split("=")[1];
  let name = args.find(a => a.startsWith("--name="))?.split("=")[1];
  let env = args.find(a => a.startsWith("--env="))?.split("=")[1];
  let rotate = args.find(a => a.startsWith("--rotate="))?.split("=")[1];
  let budget = args.find(a => a.startsWith("--budget="))?.split("=")[1];
  let platform = args.find(a => a.startsWith("--platform="))?.split("=")[1];

  // Check for piped input
  if (!key && !process.stdin.isTTY) {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    key = Buffer.concat(chunks).toString().trim();
  }

  // Interactive mode
  if (!key) {
    key = await ask("  Paste credential: ");
  }
  if (!key) { console.log(c.red("  ✗ No credential provided")); process.exit(1); }

  // Detect
  const detected = detect(key);
  if (detected) {
    console.log(c.green(`  ✨ Detected: ${detected.label}`));
    if (!platform) platform = detected.platform;
    if (!rotate) rotate = String(detected.rotation);
  } else {
    console.log(c.yellow("  ⚠ Unknown credential format"));
  }

  // Fill missing fields
  if (!name && !isPiped) name = await ask(`  Name ${platform ? `(${platform})` : ""}: `);
  if (!name) name = (platform || "key") + "-" + Date.now().toString(36);

  if (!platform && !isPiped) platform = await ask("  Platform (openai/anthropic/google/aws/...): ");
  if (!platform) platform = "unknown";

  if (!env && !isPiped) env = await ask("  Environment (production/staging/dev) [production]: ");
  if (!env) env = "production";

  if (!rotate && !isPiped) rotate = await ask("  Rotation days [90]: ");
  if (!rotate) rotate = "90";

  if (!budget && !isPiped) {
    const b = await ask("  Monthly budget limit $ (optional): ");
    if (b) budget = b;
  }

  // Confirm
  console.log("\n  " + c.bold("Summary:"));
  console.log(`  ${c.dim("Name:")}        ${name}`);
  console.log(`  ${c.dim("Platform:")}    ${platform}`);
  console.log(`  ${c.dim("Environment:")} ${env}`);
  console.log(`  ${c.dim("Rotation:")}    ${rotate} days`);
  if (budget) console.log(`  ${c.dim("Budget:")}      $${budget}/mo`);
  console.log(`  ${c.dim("Key:")}         ${key.slice(0, 8)}...${key.slice(-4)}`);
  console.log("");

  const confirm = isPiped ? "y" : await ask("  Save to vault? (Y/n): ");
  if (confirm.toLowerCase() === "n") { console.log(c.yellow("  Cancelled\n")); process.exit(0); }

  // Send to API
  try {
    const res = await fetch(`${API_BASE}/api/cli/vault`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${config.apiKey}`,
      },
      body: JSON.stringify({
        name,
        platform,
        environment: env,
        plainKey: key,
        rotationDays: parseInt(rotate),
        credentialType: detected?.type || "api_key",
        source: "cli",
      }),
    });

    if (res.ok) {
      const data = await res.json();
      console.log(c.green("  ✓ Saved to KeySentry vault"));
      if (data.credential?.id) console.log(c.dim(`  ID: ${data.credential.id}`));
      console.log(c.dim(`  Rotation due: ${new Date(Date.now() + parseInt(rotate) * 86400000).toLocaleDateString()}`));
      if (budget) console.log(c.dim(`  Budget alert: $${Math.round(budget * 0.8)} (80%)`));
      console.log("");
    } else {
      const err = await res.json().catch(() => ({}));
      console.log(c.red(`  ✗ Failed: ${err.error || res.statusText}`));
    }
  } catch (err) {
    console.log(c.red(`  ✗ Network error: ${err.message}`));
  }
}

async function scan(args) {
  console.log("\n" + c.purple("  KeySentry AI") + " — Scan for Credentials\n");
  
  let text = "";
  
  // Check for piped input
  if (!process.stdin.isTTY) {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    text = Buffer.concat(chunks).toString();
  } else {
    console.log("  Paste text to scan (Ctrl+D when done):\n");
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    text = Buffer.concat(chunks).toString();
  }

  // Scan for patterns (sorted by prefix length desc to avoid duplicates)
  const found = [];
  const seen = new Set();
  const sorted = [...PATTERNS].sort((a, b) => b.prefix.length - a.prefix.length);
  for (const p of sorted) {
    const regex = new RegExp(p.prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "[A-Za-z0-9_\\-]{8,}", "g");
    const matches = text.match(regex);
    if (matches) {
      matches.forEach(m => { if (!seen.has(m)) { seen.add(m); found.push({ key: m, ...p }); } });
    }
  }

  if (found.length === 0) {
    console.log(c.green("  ✓ No credentials detected\n"));
  } else {
    console.log(c.red(`  ⚠ Found ${found.length} credential(s):\n`));
    found.forEach((f, i) => {
      console.log(`  ${i + 1}. ${c.bold(f.label)}`);
      console.log(`     ${c.dim(f.key.slice(0, 12) + "..." + f.key.slice(-4))}`);
      console.log(`     Platform: ${f.platform} | Type: ${f.type}\n`);
    });
  }
}

function showHelp() {
  console.log(`
  ${c.purple("KeySentry AI")} CLI v${VERSION}

  ${c.bold("COMMANDS")}

    ${c.green("login")}              Authenticate with your API key
    ${c.green("vault")}              Save a credential to your vault
    ${c.green("scan")}               Scan text for exposed credentials
    ${c.green("status")}             Show connection status
    ${c.green("token")}              Print a Gateway sign-in token (for Claude Code)
    ${c.green("help")}               Show this help

  ${c.bold("VAULT OPTIONS")}

    --key=<key>        Credential value
    --name=<name>      Credential name
    --platform=<plat>  Platform (openai, anthropic, aws, etc.)
    --env=<env>        Environment (production, staging, dev)
    --rotate=<days>    Rotation schedule in days
    --budget=<amount>  Monthly budget limit in dollars

  ${c.bold("TOKEN OPTIONS")}

    --tenant <id>      Directory (tenant) ID from your Entra app
    --client <id>      Application (client) ID from your Entra app
    --info             Show who is signed in (no token printed)
    --logout           Remove the saved sign-in

  ${c.bold("EXAMPLES")}

    ${c.dim("# Interactive")}
    keysentry vault

    ${c.dim("# One-liner")}
    keysentry vault --key="sk-ant-..." --name="prod-key" --env=production

    ${c.dim("# Pipe from env")}
    echo $ANTHROPIC_API_KEY | keysentry vault --name="from-env"

    ${c.dim("# Scan a file")}
    cat .env | keysentry scan

    ${c.dim("# Scan clipboard (macOS)")}
    pbpaste | keysentry scan

    ${c.dim("# Claude Code setting (IT deploys this in managed settings)")}
    "apiKeyHelper": "keysentry token --tenant <tenant-id> --client <client-id>"
`);
}

async function status() {
  const config = loadConfig();
  console.log("\n" + c.purple("  KeySentry AI") + " — Status\n");
  if (config.apiKey) {
    console.log(c.green("  ✓ Authenticated"));
    if (config.email) console.log(c.dim(`  Email: ${config.email}`));
    console.log(c.dim(`  API: ${API_BASE}`));
    console.log(c.dim(`  Config: ${CONFIG_FILE}`));
  } else {
    console.log(c.red("  ✗ Not authenticated"));
    console.log(c.dim("  Run: keysentry login"));
  }
  console.log("");
}

// ═══ MAIN ═══
const [,, cmd, ...args] = process.argv;

switch (cmd) {
  case "login": await login(); break;
  case "vault": case "v": await vault(args); break;
  case "scan": case "s": await scan(args); break;
  case "status": await status(); break;
  case "token": process.exitCode = await tokenCommand(args); break;
  case "help": case "--help": case "-h": case undefined: showHelp(); break;
  case "--version": case "-v": console.log(VERSION); break;
  default: console.log(c.red(`  Unknown command: ${cmd}`)); showHelp();
}
