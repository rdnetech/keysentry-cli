// KeySentry CLI — `keysentry copilot-key`
//
// GitHub Copilot (VS Code Custom Endpoint, Copilot CLI) can't sign in with Entra on each request, so a signed-in
// person gets a personal Gateway key instead (ksg_p_…). It reaches their own Gateway access: requests are logged,
// budgeted and checked under their name, and turning them off in KeySentry stops the key.
//
//   keysentry copilot-key --tenant <id> --client <id>          get a key (browser sign-in if needed); copies it
//   keysentry copilot-key --tenant <id> --client <id> --print  print the saved key only (for COPILOT_PROVIDER_API_KEY)
//   keysentry copilot-key --tenant <id> --client <id> --forget remove the saved key from this computer
//
// The key is saved like the sign-in (macOS Keychain, elsewhere ~/.keysentry/sso/ readable only by you).
// With --print, stdout carries only the key; every message goes to stderr.

import { spawnSync } from "child_process";
import { platform } from "os";
import { getToken, store, TokenError } from "./sso.mjs";

const API_BASE = "https://www.getkeysentry.com";
const GATEWAY = "https://gateway.getkeysentry.com";
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const err = (msg) => process.stderr.write(`keysentry: ${msg}\n`);

function parseArgs(args) {
  const out = { tenant: "", client: "", print: false, forget: false };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const [flag, inline] = a.includes("=") ? [a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1)] : [a, undefined];
    const value = () => (inline !== undefined ? inline : args[++i] ?? "");
    if (flag === "--tenant") out.tenant = value().trim().toLowerCase();
    else if (flag === "--client") out.client = value().trim().toLowerCase();
    else if (flag === "--print") out.print = true;
    else if (flag === "--forget") out.forget = true;
    else throw new TokenError(`unknown option ${flag}. Use: keysentry copilot-key --tenant <id> --client <id> [--print | --forget]`);
  }
  if (!GUID.test(out.tenant)) throw new TokenError("--tenant must be your Directory (tenant) ID, a GUID from the Entra app's Overview page.");
  if (!GUID.test(out.client)) throw new TokenError("--client must be the Application (client) ID, a GUID from the Entra app's Overview page.");
  return out;
}

const slots = (o) => ({ active: `${o.tenant}.${o.client}.copilot`, pending: `${o.tenant}.${o.client}.copilot-pending` });

// A key that was waiting for approval: ask the Gateway whether it works yet. Approved → it becomes the saved key.
async function settlePending(s, o) {
  const { active, pending } = slots(o);
  const key = s.get(pending);
  if (!key) return;
  let status = 0;
  try {
    const r = await fetch(`${GATEWAY}/v1/models`, { headers: { "x-api-key": key, "anthropic-version": "2023-06-01" }, signal: AbortSignal.timeout(10_000) });
    status = r.status;
  } catch { return; } // offline: keep things as they are
  if (status === 200) { s.set(active, key); s.remove(pending); err("your new Copilot key was approved and is now in use."); }
  else if (status === 401) { s.remove(pending); err("the Copilot key that was waiting for approval was revoked or expired."); }
}

function copyToClipboard(text) {
  const os = platform();
  const tries = os === "darwin" ? [["pbcopy", []]] : os === "win32" ? [["clip", []]] : [["wl-copy", []], ["xclip", ["-selection", "clipboard"]], ["xsel", ["--clipboard", "--input"]]];
  for (const [cmd, args] of tries) {
    try { const r = spawnSync(cmd, args, { input: text }); if (r.status === 0) return true; } catch { /* try the next one */ }
  }
  return false;
}

export async function copilotKeyCommand(args) {
  try {
    const o = parseArgs(args);
    const s = store();
    const { active, pending } = slots(o);

    if (o.forget) {
      s.remove(active); s.remove(pending);
      err(`removed the saved Copilot key from ${s.name}. It still works until an administrator revokes it.`);
      return 0;
    }

    if (o.print) {
      await settlePending(s, o);
      const key = s.get(active);
      if (!key) throw new TokenError(`no Copilot key on this computer. In a terminal, run: keysentry copilot-key --tenant ${o.tenant} --client ${o.client}`);
      process.stdout.write(key + "\n");
      return 0;
    }

    // Get a key: sign in (saved sign-in, or the browser), then ask KeySentry for this person's key
    const idToken = await getToken({ tenant: o.tenant, client: o.client, info: true });
    let res, data = {};
    try {
      res = await fetch(`${API_BASE}/api/cli/copilot-key`, { method: "POST", headers: { Authorization: `Bearer ${idToken}` }, signal: AbortSignal.timeout(20_000) });
      data = await res.json().catch(() => ({}));
    } catch {
      throw new TokenError("could not reach KeySentry (www.getkeysentry.com). Check your network.");
    }
    if (!res.ok || !data.key) throw new TokenError(typeof data.error === "string" ? data.error : `KeySentry refused the request (HTTP ${res.status}).`);

    if (data.status === "active") { s.set(active, data.key); s.remove(pending); }
    else s.set(pending, data.key);
    err(data.message || "");
    err(`key ${data.keyPrefix}… for ${data.person || "you"}, saved in ${s.name}.`);
    if (copyToClipboard(data.key)) {
      err("the key is copied to your clipboard. In VS Code, paste it when it asks for the API key of the KeySentry models.");
    } else {
      err("couldn't reach a clipboard tool. Copy the key on the next line into VS Code when it asks for the API key of the KeySentry models:");
      process.stdout.write(data.key + "\n");
    }
    err(`Copilot CLI reads the saved key itself: COPILOT_PROVIDER_API_KEY="$(keysentry copilot-key --tenant ${o.tenant} --client ${o.client} --print)"`);
    return 0;
  } catch (e) {
    err(e instanceof TokenError ? e.message : `unexpected error: ${e && e.message ? e.message : e}`);
    return 1;
  }
}
