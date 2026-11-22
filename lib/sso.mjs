// KeySentry CLI — `keysentry token`
//
// Prints a short-lived Microsoft Entra ID token for the KeySentry Gateway.
// Built for Claude Code's `apiKeyHelper` setting:
//
//   "apiKeyHelper": "keysentry token --tenant <tenant-id> --client <client-id>"
//
// Rules this file keeps:
//   - stdout carries ONLY the token (Claude Code fails on any extra line).
//     Every message goes to stderr.
//   - Tokens are never logged, never put in a command line, never sent
//     anywhere except Microsoft's sign-in service.
//   - Saved sign-in: macOS Keychain; elsewhere ~/.keysentry/sso/ (folder 0700,
//     file 0600).
//   - No dependencies. Node built-ins only.

import { createServer } from "http";
import { spawn, spawnSync } from "child_process";
import { createHash, randomBytes } from "crypto";
import { homedir, platform } from "os";
import { join } from "path";
import {
  chmodSync, existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync,
} from "fs";

const LOGIN_HOST = "https://login.microsoftonline.com";
const SCOPE = "openid profile email offline_access";
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Hand out a saved token only while it has at least this long left. Claude
// Code reuses a helper's output for 5 minutes by default, so 10 minutes keeps
// the Gateway from ever seeing an expired one.
const MIN_REMAINING_SEC = 10 * 60;
const SIGN_IN_TIMEOUT_MS = 3 * 60 * 1000;
const KEYCHAIN_SERVICE = "keysentry-sso";

const err = (msg) => process.stderr.write(`keysentry: ${msg}\n`);

class TokenError extends Error {}

// ─── Arguments ────────────────────────────────────────────────────────────

function parseArgs(args) {
  const out = { tenant: "", client: "", logout: false, info: false };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const [flag, inline] = a.includes("=") ? [a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1)] : [a, undefined];
    const value = () => (inline !== undefined ? inline : args[++i] ?? "");
    if (flag === "--tenant") out.tenant = value().trim();
    else if (flag === "--client") out.client = value().trim();
    else if (flag === "--logout") out.logout = true;
    else if (flag === "--info") out.info = true;
    else throw new TokenError(`unknown option ${flag}. Use: keysentry token --tenant <id> --client <id> [--info | --logout]`);
  }
  if (!GUID.test(out.tenant)) throw new TokenError("--tenant must be your Directory (tenant) ID, a GUID from the Entra app's Overview page.");
  if (!GUID.test(out.client)) throw new TokenError("--client must be the Application (client) ID, a GUID from the Entra app's Overview page.");
  out.tenant = out.tenant.toLowerCase();
  out.client = out.client.toLowerCase();
  return out;
}

// ─── Saved sign-in ────────────────────────────────────────────────────────
// Two values per tenant+app: the ID token (≈1 hour) and the refresh token.

function keychainStore() {
  const run = (args, input) => spawnSync("/usr/bin/security", args, { input, encoding: "utf8" });
  return {
    name: "macOS Keychain",
    get(account) {
      const r = run(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"]);
      return r.status === 0 ? r.stdout.replace(/\n$/, "") : "";
    },
    set(account, value) {
      // Value goes in on stdin (interactive mode), not on the command line,
      // so it never shows up in a process listing.
      run(["-i"], `add-generic-password -U -s ${KEYCHAIN_SERVICE} -a ${account} -w ${value}\n`);
      if (this.get(account) === value) return;
      // Interactive mode has a line-length limit on some macOS versions. Fall
      // back to the argument form (visible only to this user's own processes
      // for the instant the command runs).
      const r = run(["add-generic-password", "-U", "-s", KEYCHAIN_SERVICE, "-a", account, "-w", value]);
      if (r.status !== 0 || this.get(account) !== value) throw new TokenError("could not save the sign-in to the macOS Keychain.");
    },
    remove(account) {
      run(["delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account]);
    },
  };
}

function fileStore() {
  const dir = join(homedir(), ".keysentry", "sso");
  const pathFor = (account) => join(dir, account.replace(/[^a-z0-9._-]/gi, "_") + ".json");
  return {
    name: dir,
    get(account) {
      const p = pathFor(account);
      if (!existsSync(p)) return "";
      try { return String(JSON.parse(readFileSync(p, "utf8")).value || ""); } catch { return ""; }
    },
    set(account, value) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      chmodSync(dir, 0o700);
      const p = pathFor(account);
      const tmp = `${p}.${process.pid}.tmp`;
      writeFileSync(tmp, JSON.stringify({ value }), { mode: 0o600 });
      chmodSync(tmp, 0o600);
      renameSync(tmp, p);
    },
    remove(account) {
      const p = pathFor(account);
      if (existsSync(p)) unlinkSync(p);
    },
  };
}

const useKeychain = () => platform() === "darwin" && existsSync("/usr/bin/security");
const store = () => (useKeychain() ? keychainStore() : fileStore());

// ─── Token helpers ────────────────────────────────────────────────────────

function claimsOf(jwt) {
  try {
    const part = jwt.split(".")[1];
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

// Light checks only: the Gateway verifies the signature. These stop us from
// handing out a token for the wrong tenant or app, or one about to expire.
function usable(idToken, opts, minRemaining = MIN_REMAINING_SEC) {
  if (!idToken) return false;
  const c = claimsOf(idToken);
  if (!c) return false;
  const now = Math.floor(Date.now() / 1000);
  return c.aud === opts.client && String(c.tid || "").toLowerCase() === opts.tenant && typeof c.exp === "number" && c.exp - now >= minRemaining;
}

async function tokenRequest(opts, params) {
  const body = new URLSearchParams({ client_id: opts.client, scope: SCOPE, ...params });
  let res;
  try {
    res = await fetch(`${LOGIN_HOST}/${opts.tenant}/oauth2/v2.0/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    throw new TokenError("could not reach Microsoft sign-in (login.microsoftonline.com). Check your network.");
  }
  let data = {};
  try { data = await res.json(); } catch { /* handled below */ }
  if (!res.ok || !data.id_token) {
    // error + first line of error_description are safe to show (no tokens in them).
    const code = typeof data.error === "string" ? data.error : `HTTP ${res.status}`;
    const desc = typeof data.error_description === "string" ? data.error_description.split(/\r?\n/)[0] : "";
    const e = new TokenError(`Microsoft sign-in refused the request (${code})${desc ? `: ${desc}` : ""}`);
    e.code = code;
    throw e;
  }
  return data;
}

function save(opts, s, data) {
  const base = `${opts.tenant}.${opts.client}`;
  s.set(`${base}.id`, data.id_token);
  if (data.refresh_token) s.set(`${base}.refresh`, data.refresh_token);
}

// ─── Browser sign-in (authorization code + PKCE, loopback redirect) ──────

function openBrowser(url) {
  const os = platform();
  const [cmd, args] =
    os === "darwin" ? ["open", [url]]
    : os === "win32" ? ["rundll32", ["url.dll,FileProtocolHandler", url]]
    : ["xdg-open", [url]];
  try {
    const child = spawn(cmd, args, { stdio: "ignore", detached: true });
    child.on("error", () => {});
    child.unref();
  } catch { /* the URL is printed too */ }
}

const page = (title, line) =>
  `<!doctype html><meta charset="utf-8"><title>KeySentry</title>` +
  `<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;color:#222">` +
  `<h2>${title}</h2><p>${line}</p></body>`;

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));

async function browserSignIn(opts) {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const state = randomBytes(16).toString("base64url");
  const nonce = randomBytes(16).toString("base64url");

  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = server.address().port;
  const redirectUri = `http://127.0.0.1:${port}/callback`;

  const authUrl = `${LOGIN_HOST}/${opts.tenant}/oauth2/v2.0/authorize?` + new URLSearchParams({
    client_id: opts.client,
    response_type: "code",
    response_mode: "query",
    redirect_uri: redirectUri,
    scope: SCOPE,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "select_account",
  });

  err("sign in with your work Microsoft account in the browser window that just opened.");
  err(`if no window opened, open this link: ${authUrl}`);
  openBrowser(authUrl);

  try {
    const code = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new TokenError("sign-in timed out after 3 minutes. Run the command again.")), SIGN_IN_TIMEOUT_MS);
      server.on("request", (req, res) => {
        const url = new URL(req.url || "/", redirectUri);
        if (url.pathname !== "/callback") { res.writeHead(404).end(); return; }
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.setHeader("Cache-Control", "no-store");
        if (url.searchParams.get("state") !== state) {
          res.writeHead(400).end(page("Sign-in not completed", "This response did not match the sign-in KeySentry started. Close this tab and try again."));
          return; // keep waiting for the real response
        }
        clearTimeout(timer);
        const e = url.searchParams.get("error");
        if (e) {
          const desc = (url.searchParams.get("error_description") || "").split(/\r?\n/)[0];
          res.writeHead(400).end(page("Sign-in not completed", `Microsoft returned: ${escapeHtml(e)}. ${escapeHtml(desc)}`));
          reject(new TokenError(`Microsoft sign-in returned ${e}${desc ? `: ${desc}` : ""}`));
          return;
        }
        const c = url.searchParams.get("code");
        if (!c) {
          res.writeHead(400).end(page("Sign-in not completed", "No sign-in code came back. Close this tab and try again."));
          reject(new TokenError("no sign-in code came back from Microsoft."));
          return;
        }
        res.writeHead(200).end(page("Signed in to KeySentry", "You can close this tab and go back to your terminal."));
        resolve(c);
      });
    });

    const data = await tokenRequest(opts, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    });
    const c = claimsOf(data.id_token);
    if (!c || c.nonce !== nonce) throw new TokenError("the sign-in response failed its replay check. Run the command again.");
    return data;
  } finally {
    server.close();
  }
}

// ─── Command ──────────────────────────────────────────────────────────────

async function getToken(opts) {
  const s = store();
  const base = `${opts.tenant}.${opts.client}`;

  const saved = s.get(`${base}.id`);
  if (usable(saved, opts)) return saved;

  const refresh = s.get(`${base}.refresh`);
  if (refresh) {
    try {
      const data = await tokenRequest(opts, { grant_type: "refresh_token", refresh_token: refresh });
      if (usable(data.id_token, opts, 60)) {
        save(opts, s, data);
        return data.id_token;
      }
    } catch (e) {
      // invalid_grant = sign-in expired or was revoked (password change,
      // admin sign-out, account disabled). Fall through to a fresh sign-in.
      // Anything else (network down) is a real failure.
      if (e.code !== "invalid_grant" && e.code !== "interaction_required") throw e;
      s.remove(`${base}.refresh`);
      s.remove(`${base}.id`);
    }
  }

  // Browser sign-in only when a person is at the terminal. When Claude Code
  // (or any tool) runs us with stdout captured, it won't wait for a browser,
  // so stop right away with the command to run instead.
  if (!process.stdout.isTTY && !opts.info) {
    throw new TokenError(`not signed in to the KeySentry Gateway on this computer. In a terminal, run: keysentry token --tenant ${opts.tenant} --client ${opts.client} --info`);
  }
  const data = await browserSignIn(opts);
  if (!usable(data.id_token, opts, 60)) throw new TokenError("Microsoft returned a token for a different tenant or app. Check --tenant and --client.");
  save(opts, s, data);
  err("signed in.");
  return data.id_token;
}

export async function tokenCommand(args) {
  try {
    const opts = parseArgs(args);
    const s = store();
    const base = `${opts.tenant}.${opts.client}`;

    if (opts.logout) {
      s.remove(`${base}.id`);
      s.remove(`${base}.refresh`);
      err(`signed out (removed the saved sign-in from ${s.name}).`);
      return 0;
    }

    const token = await getToken(opts);

    if (opts.info) {
      const c = claimsOf(token) || {};
      const mins = Math.max(0, Math.floor((c.exp - Date.now() / 1000) / 60));
      err(`signed in as ${c.preferred_username || c.email || c.upn || "unknown"}; token good for about ${mins} more minutes; saved in ${s.name}.`);
      return 0;
    }

    process.stdout.write(token + "\n");
    return 0;
  } catch (e) {
    err(e instanceof TokenError ? e.message : `unexpected error: ${e && e.message ? e.message : e}`);
    return 1;
  }
}
