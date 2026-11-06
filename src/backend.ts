// Adapter over Tauri commands. Command names follow upstream; Mirsa-specific ones are listed in API.md.
// Outside Tauri (browser preview) a clearly-labelled demo mode simulates nothing real: it only drives the UI.
export type Device = { name: string; id: number; udid: string; connectionType: string; version: string };
export type StepUpdate = { updateType: "started" | "finished" | "failed"; stepId: string; extraDetails?: { message?: string } | string | null };
export const inTauri = typeof (window as any).__TAURI_INTERNALS__ !== "undefined";
async function inv<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}
async function listen<T>(ev: string, cb: (p: T) => void): Promise<() => void> {
  const { listen } = await import("@tauri-apps/api/event");
  return listen<T>(ev, (e) => cb(e.payload));
}
export const errText = (e: unknown): string => {
  const m = typeof e === "string" ? e : e && typeof e === "object" && typeof (e as any).message === "string" ? (e as any).message : "";
  return m.replace(/\s+/g, " ").trim().slice(0, 300);
};
export type TfaParams = { lastError?: string | null; unknown?: boolean; sms?: boolean; numbers?: Array<{ id: number; lastTwoDigits?: string; numberWithDialCode?: string; pushMode?: string }>; selectedNumberId?: number | null };
/** Full bounded details (backend already sanitized: stage, code, chain, log path). */
export const errDetails = (e: unknown): string => {
  if (!e || typeof e !== "object") return "";
  const o = e as any; let t = typeof o.details === "string" ? o.details : "";
  if (!t && o.diagnostic && typeof o.diagnostic === "object") { const g = o.diagnostic; t = ["Stage " + (g.stage ?? "?") + (g.code != null ? "; code " + g.code : ""), ...(Array.isArray(g.chain) ? g.chain.map(String) : []), g.logPath ? "Log: " + g.logPath : ""].filter(Boolean).join("\n"); }
  return t.replace(/\r/g, "").trim().slice(0, 6000);
};
export const api = {
  async listDevices(): Promise<Device[]> {
    if (!inTauri) return [];
    const r = await inv<Array<{ Ok?: Device } | Device>>("list_devices");
    return r.map((x: any) => (x.Ok ?? x)).filter((x: any) => x && x.udid);
  },
  selectDevice: (d: Device | null) => inTauri ? inv<void>("set_selected_device", { device: d }) : Promise.resolve(),
  cancelPairing: () => inTauri ? inv<void>("cancel_pairing") : Promise.resolve(),
  exportPairing: () => inTauri ? inv<void>("export_pairing_cmd") : Promise.resolve(),
  /** Password is passed once, never stored (saveCredentials=false). */
  login: (email: string, password: string) => inTauri ? inv<void>("login_new", { email, password, anisetteServer: "ani.iloader.app", saveCredentials: false }) : Promise.reject("Desktop backend not available in browser preview"),
  loggedInAs: () => inTauri ? inv<string | null>("logged_in_as") : Promise.resolve(null),
  signOut: () => inTauri ? inv<void>("invalidate_account") : Promise.resolve(),
  /** Native clipboard command (backend), falls back to the browser clipboard. */
  async copyDetails(text: string) {
    if (inTauri) { try { await inv<void>("copy_error_details", { details: text }); return; } catch { /* fall back */ } }
    await navigator.clipboard.writeText(text);
  },
  onTwoFactor: (cb: (p: TfaParams) => void) => inTauri ? listen<TfaParams>("2fa-required", cb) : Promise.resolve(() => {}),
  async sendTwoFactor(code: string) { if (inTauri) { const { emit } = await import("@tauri-apps/api/event"); await emit("2fa-recieved", code); } },
  install: () => inTauri ? inv<{ bundleIdentifier: string; version: string; requiresFirstOpen: boolean }>("install_mirsa_operation") : Promise.reject("Desktop backend not available in browser preview"),
  async chooseLocalIpa(): Promise<{ token: string; name: string } | null> { return (await inv<{ token: string; name: string } | null>("choose_local_ipa")) ?? null; },
  installLocal: (token: string) => inv<void>("install_local_ipa_operation", { token }),
  finishSetup: (email: string, password: string) => inv<{ status: string; sessionId: string }>("finish_mirsa_setup", { email, password }),
  handoffStatus: () => inv<{ status: "waiting" | "consumed" | "rejected" }>("mirsa_handoff_status"),
  async sendTwoFactorAction(a: { action: "devices" | "resend" | "cancel" | "sms"; numberId?: number }) { if (inTauri) { const { emit } = await import("@tauri-apps/api/event"); await emit("2fa-recieved", a); } },
  onMaxCerts: (cb: (c: any[]) => void) => inTauri ? listen<any[]>("max-certs-reached", cb) : Promise.resolve(() => {}),
  async answerCerts(ids: string[] | null) { if (inTauri) { const { emit } = await import("@tauri-apps/api/event"); await emit("max-certs-response", ids); } },
  onOperation: (id: string, cb: (u: StepUpdate) => void) => inTauri ? listen<StepUpdate>("operation_" + id, cb) : Promise.resolve(() => {}),
  openUrl: async (u: string) => { const { openUrl } = await import("@tauri-apps/plugin-opener"); return openUrl(u); },
};
