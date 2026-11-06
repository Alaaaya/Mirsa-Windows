import { useCallback, useEffect, useRef, useState } from "react";
import { api, errText, inTauri, type Device, type StepUpdate } from "./backend";
import { dict, type Key, type Lang } from "./i18n";

const STEPS = ["login", "download", "install", "pairing", "open", "finish"] as const;
const LOCAL_STEPS = ["login", "validate", "install"] as const;
type Phase = "idle" | "running" | "open" | "finishing" | "done" | "error";
const Logo = ({ s = 30 }: { s?: number }) => (<img src="/mirsa.svg" width={s} height={s} alt="" />);
const Ico = ({ d }: { d: string }) => (<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d={d} /></svg>);

export default function App() {
  const [lang, setLang] = useState<Lang>(() => { const l = localStorage.getItem("lang"); return l === "ar" || l === "en" ? l : "en"; });
  const t = (k: Key) => dict[lang][k];
  const [devices, setDevices] = useState<Device[]>([]);
  const [sel, setSel] = useState<Device | null>(null);
  const [email, setEmail] = useState(""); const [pw, setPw] = useState(""); const [showPw, setShowPw] = useState(false);
  const [phase, setPhase] = useState<Phase>("idle");
  const [step, setStep] = useState(0); const [msg, setMsg] = useState("");
  const [tfa, setTfa] = useState(false); const [code, setCode] = useState("");
  const [pairMsg, setPairMsg] = useState("");
  const [certs, setCerts] = useState<any[] | null>(null); const [pick, setPick] = useState<string[]>([]);
  const [source, setSource] = useState<"latest" | "local">("latest"); const [local, setLocal] = useState<{ token: string; name: string } | null>(null); const [installedLocal, setInstalledLocal] = useState(false);
  const [warn, setWarn] = useState(""); const [selErr, setSelErr] = useState("");
  const emailRef = useRef(""); const pwRef = useRef("");
  emailRef.current = email; pwRef.current = pw;
  const safe = (e: unknown) => { let m = errText(e) || t("failed"); for (const s of [pwRef.current, emailRef.current]) if (s) m = m.split(s).join("***"); return m; };
  const unsub = useRef<Array<() => void>>([]);

  const busy = phase === "running" || phase === "finishing" || phase === "open" || phase === "done";
  const isLocal = source === "local";
  const steps: readonly string[] = isLocal ? LOCAL_STEPS : STEPS;
  const busyRef = useRef(busy); busyRef.current = busy;
  const refresh = useCallback(async () => {
    if (busyRef.current) return;
    try {
      const d = await api.listDevices();
      if (busyRef.current) return;
      setDevices((prev) => (prev.length === d.length && prev.every((p, i) => p.udid === d[i].udid && p.id === d[i].id) ? prev : d));
      setSel((c) => { const same = c && d.find((x) => x.udid === c.udid && x.id === c.id); return same ? c : d[0] ?? null; });
    } catch { if (!busyRef.current) { setDevices([]); setSel(null); } }
  }, []);
  useEffect(() => { refresh(); const i = setInterval(refresh, 3000); return () => clearInterval(i); }, [refresh]);
  const selKey = sel ? sel.udid + ":" + sel.id : "";
  useEffect(() => {
    setSelErr(""); if (busyRef.current) return;
    api.selectDevice(sel).catch((e) => setSelErr(safe(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selKey]);
  useEffect(() => { localStorage.setItem("lang", lang); document.documentElement.lang = lang; }, [lang]);
  useEffect(() => () => unsub.current.forEach((f) => f()), []);

  const clearSecrets = () => { setPw(""); setCode(""); };
  const pickIpa = async () => { setLocal(null); try { const r = await api.chooseLocalIpa(); setLocal(r); } catch (e) { setMsg(safe(e)); setPhase("error"); } };
  const fail = (e: unknown) => { setMsg(safe(e)); setPhase("error"); setTfa(false); setCerts(null); clearSecrets(); };

  const start = async () => {
    if (!email || !pw) { setMsg(t("needFields")); setPhase("error"); return; }
    if (!sel) { setMsg(t("needDevice")); setPhase("error"); return; }
    if (isLocal && !local) { setMsg(t("needIpa")); setPhase("error"); return; }
    setMsg(""); setPhase("running"); setStep(0);
    unsub.current.forEach((f) => f()); unsub.current = [];
    try {
    unsub.current = [await api.onTwoFactor(() => setTfa(true)), await api.onMaxCerts((c) => { const ok = (Array.isArray(c) ? c : []).filter((x: any) => typeof x?.serialNumber === "string" && x.serialNumber); if (!ok.length) { api.answerCerts(null); return; } setPick([]); setCerts(ok); }),
      await api.onOperation(isLocal ? "install_local" : "install_mirsa", (u: StepUpdate) => {
        const i = steps.indexOf(u.stepId);
        if (u.updateType === "failed") fail(u.extraDetails ?? t("failed"));
        else if (i >= 0) setStep(u.updateType === "finished" ? i + 1 : i);
      })];
      await api.login(email, pw); setCode(""); setStep(1);
      if (isLocal) { await api.installLocal(local!.token); clearSecrets(); setInstalledLocal(true); setLocal(null); setStep(LOCAL_STEPS.length); setPhase("done"); }
      else { await api.install(); setStep(4); setPhase("open"); }
    } catch (e) { fail(e); }
  };
  const sendCode = async (cancel = false) => { const c = cancel ? "" : code.trim(); setCode(""); setTfa(false); await api.sendTwoFactor(c).catch(() => {}); };
  const finish = async () => {
    setWarn(""); setPhase("finishing"); setStep(5);
    try {
      await api.finishSetup(email, pw);
      const end = Date.now() + 90000;
      while (Date.now() < end) {
        const s = (await api.handoffStatus()).status;
        if (s === "consumed") { clearSecrets(); setPhase("done"); setStep(STEPS.length); return; }
        if (s === "rejected") { setWarn(t("rejected")); setPhase("open"); return; }
        await new Promise((r) => setTimeout(r, 2000));
      }
      setWarn(t("timeout")); setPhase("open");
    } catch (e) { setWarn(safe(e)); setPhase("open"); }
  };
  const exportPair = async () => { setPairMsg(""); try { await api.exportPairing(); } catch (e) { setPairMsg(t("exportFail") + ": " + safe(e)); } };
  const pct = Math.round((Math.min(step, steps.length) / steps.length) * 100);
  return (<div className="app" dir="ltr">
    <div className="glow g1" /><div className="glow g2" />
    <header data-tauri-drag-region>
      <div className="brand"><Logo /><span>Mirsa</span></div>
      <button className="lang" onClick={() => setLang(lang === "en" ? "ar" : "en")}>{t("lang")}</button>
    </header>
    <main>
      <section className="card device">
        <div className="phone"><div className="screen"><Logo s={56} /></div></div>
        {sel ? (<div className="status ok"><span className="dot"><Ico d="M5 12l5 5L20 7" /></span>{t("connected")}</div>)
          : (<div className="status"><span className="dot off"><Ico d="M12 8v5M12 17h.01" /></span>{t("noDevice")}</div>)}
        {sel && <div className="muted">{sel.name} · iOS {sel.version}</div>}
        {devices.length > 1 && (<select disabled={busy} value={sel?.udid} onChange={(e) => setSel(devices.find((d) => d.udid === e.target.value) ?? null)} aria-label={t("chooseDevice")}>
          {devices.map((d) => <option key={d.udid} value={d.udid}>{d.name}</option>)}</select>)}
        {selErr && <div className="err" role="alert">{selErr}</div>}
        {!sel && <p className="muted">{t("plug")}</p>}
        <ul className="guide"><li>{t("g1")}</li><li>{t("g2")}</li><li>{t("g3")}</li></ul>
        <button className="link" onClick={refresh} disabled={busy}>{t("refresh")}</button>
      </section>
      <section className="right">
        {phase === "open" || phase === "finishing" || phase === "done" ? (
          <div className="card done"><h2>{installedLocal ? t("appInstalled") : phase === "done" ? t("setupDone") : t("doneTitle")}</h2>
            {installedLocal ? (<div className="status ok"><span className="dot"><Ico d="M5 12l5 5L20 7" /></span>{t("appInstalled")}</div>) : phase !== "done" ? (<><p className="muted">{t("doneSub")}</p>{warn && <div className="err" role="alert">{warn}</div>}<button className="primary" onClick={finish} disabled={phase === "finishing"}>{phase === "finishing" ? t("waiting") : t("finishBtn")}</button></>)
              : (<div className="status ok"><span className="dot"><Ico d="M5 12l5 5L20 7" /></span>{t("done")}</div>)}</div>
        ) : (<>
          <div className="seg" role="radiogroup">{(["latest", "local"] as const).map((s) => (<button key={s} type="button" role="radio" aria-checked={source === s} className={source === s ? "on" : ""} disabled={busy} onClick={() => setSource(s)}>{t(s === "latest" ? "srcLatest" : "srcLocal")}</button>))}</div>
          {isLocal && (<div className="card pair"><div className="pico"><Ico d="M7 3h7l5 5v13H7zM14 3v5h5" /></div><div className="ptext"><b>{local ? local.name || t("ipaChosen") : t("ipaNone")}</b><span className="muted">{t("ipaNote")}</span></div><button className="ghost" onClick={pickIpa} disabled={busy}>{t("choose")}</button></div>)}
          <button className="primary" onClick={start} disabled={busy}><Ico d="M12 4v11m0 0l-4-4m4 4l4-4M5 20h14" />{t(isLocal ? "installIpa" : "install")}</button>
          <label className="field"><Ico d="M4 6h16v12H4zM4 7l8 6 8-6" /><input type="email" autoComplete="off" spellCheck={false} placeholder={t("appleId")} value={email} onChange={(e) => setEmail(e.target.value)} disabled={busy} /></label>
          <label className="field"><Ico d="M6 11h12v9H6zM8 11V8a4 4 0 018 0v3" /><input type={showPw ? "text" : "password"} autoComplete="off" placeholder={t("password")} value={pw} onChange={(e) => setPw(e.target.value)} disabled={busy} />
            <button type="button" className="eye" aria-label={showPw ? t("hide") : t("show")} onClick={() => setShowPw(!showPw)}><Ico d={showPw ? "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 9a3 3 0 100 6 3 3 0 000-6" : "M3 3l18 18M10 6.2A9 9 0 0112 6c6 0 10 6 10 6a17 17 0 01-3 3.5M6.5 7.5A17 17 0 002 12s4 7 10 7a9 9 0 004-1"} /></button></label>
          <p className="hint">{t("privacy")}</p>
        </>)}
        {phase === "error" && <div className="err" role="alert">{msg} <button className="link" onClick={() => setPhase("idle")}>{t("tryAgain")}</button></div>}
        <div className="card pair"><div className="pico"><Ico d="M7 3h7l5 5v13H7zM14 3v5h5" /></div>
          <div className="ptext"><b>{t("pairTitle")}</b><span className="errtxt warnc">{t("pairWarn")}</span><span className="muted">{t("pairSub")}</span>{pairMsg && <span className="errtxt">{pairMsg}</span>}</div>
          <button className="ghost" onClick={exportPair} disabled={!sel || busy}>{t("export")}</button></div>
      </section>
    </main>
    <footer>
      <ol className="steps">{steps.map((s, i) => (<li key={s} className={i < step ? "d" : i === step && busy ? "a" : ""}>{t(("s_" + s) as Key)}</li>))}</ol>
      <div className="bar"><div className="track"><div className="fill" style={{ width: pct + "%" }} /></div><span>{pct}%</span></div>
      {!inTauri && <div className="muted tiny">{t("demo")}</div>}
    </footer>
    {certs && (<div className="overlay"><div className="modal card" role="dialog" aria-modal="true"><h3>{t("certTitle")}</h3><p className="muted">{t("certSub")}</p>
      <div className="certs">{certs.map((c: any) => { const id: string = c.serialNumber; const on = pick.includes(id); return (<label key={id} className="cert"><input type="checkbox" checked={on} onChange={() => setPick(on ? pick.filter((x) => x !== id) : [...pick, id])} /><span>{c.name ?? c.machineName ?? id}<small className="muted">{id}</small></span></label>); })}</div>
      <div className="row"><button className="ghost" onClick={() => { api.answerCerts(null); setCerts(null); }}>{t("cancel")}</button><button className="primary sm" disabled={!pick.length} onClick={() => { api.answerCerts(pick); setCerts(null); }}>{t("confirm")}</button></div></div></div>)}
    {tfa && (<div className="overlay"><div className="modal card" role="dialog" aria-modal="true"><h3>{t("twoTitle")}</h3><p className="muted">{t("twoSub")}</p>
      <input className="code" inputMode="numeric" maxLength={6} autoFocus value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} onKeyDown={(e) => e.key === "Enter" && code.length === 6 && sendCode()} />
      <div className="row"><button className="ghost" onClick={() => sendCode(true)}>{t("cancel")}</button><button className="primary sm" disabled={code.length !== 6} onClick={() => sendCode()}>{t("confirm")}</button></div></div></div>)}
  </div>);
}
