import { useCallback, useEffect, useState } from "react";

import "./integrity.css";
import { SharedRecords } from "./SharedRecords";
import { AuditHistory, type HistoryEvent } from "./AuditHistory";
import { EvidenceEditor } from "./EvidenceEditor";
import "./history.css";

type Role = "USER" | "ADMIN" | "AUDITOR";
interface User { id: string; name: string; role: Role }
interface RecordItem { id: string; owner_id: string; owner_name?: string; title: string; content: string; created_at: string; updated_at: string; is_shared: number; revision: number }
interface LogItem extends HistoryEvent {
  event_id: string; actor_id: string | null; actor_name: string; actor_role: string;
  session_id: string | null; occurred_at: string; ip_address: string | null; user_agent: string | null;
  action: string; record_id: string | null; field_name: string | null;
  old_value: string | null; new_value: string | null; result: string;
}
interface MetalogItem extends HistoryEvent {
  event_id: string; actor_id: string | null; actor_name: string; actor_role: string;
  session_id: string | null; occurred_at: string; ip_address: string | null; user_agent: string | null;
  action: string; resource: string; result: string; context_json: string | null;
}
interface AdminActivityItem extends MetalogItem {
  record_id: string | null; field_name: string | null; old_value: string | null;
  new_value: string | null; source: "LOG" | "METALOG";
}
interface IntegrityReport {
  status: "INTEGRITY_OK" | "INTEGRITY_FAILED" | "INTEGRITY_UNVERIFIABLE";
  reviewed: number; counts: { logs: number; metalogs: number; signed: number; validContentHashes: number; validSignatures: number; legacy: number };
  firstInconsistentEvent: { sequence: number; event_id: string; code: string } | null;
  errors: Array<{ code: string; sequence?: number; event_id?: string }>;
}
interface LabSource { source: "LOG" | "METALOG"; event_id: string; occurred_at: string; actor_name: string; actor_role: string; action: string }
interface LabCopy {
  copyId: string; source: string; sourceEventId: string; hasSignature: boolean; revision: number;
  original: Record<string, unknown>; working: Record<string, unknown>;
}

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers: { ...(options.body ? { "content-type": "application/json" } : {}), ...options.headers },
  });
  const result: unknown = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = typeof result === "object" && result !== null && "error" in result
      ? String(result.error)
      : "No se pudo completar la solicitud.";
    throw Object.assign(new Error(message), { status: response.status });
  }
  return result as T;
}

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [records, setRecords] = useState<RecordItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [auditBusy, setAuditBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const [specialRole, setSpecialRole] = useState<"ADMIN" | "AUDITOR">("ADMIN");
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingRevision, setEditingRevision] = useState<number | null>(null);
  const [logs, setLogs] = useState<LogItem[]>([]);
  const [logCursor, setLogCursor] = useState<number | null>(null);
  const [logAction, setLogAction] = useState("");
  const [logActions, setLogActions] = useState<string[]>([]);
  const [logError, setLogError] = useState("");
  const [metalogs, setMetalogs] = useState<MetalogItem[]>([]);
  const [metalogCursor, setMetalogCursor] = useState<number | null>(null);
  const [metalogAction, setMetalogAction] = useState("");
  const [metalogActions, setMetalogActions] = useState<string[]>([]);
  const [historyBusy, setHistoryBusy] = useState(false);
  const [selectedEvidence, setSelectedEvidence] = useState<{ source: "LOG" | "METALOG"; event: HistoryEvent } | null>(null);
  const [evidenceError, setEvidenceError] = useState("");
  const [metalogError, setMetalogError] = useState("");
  const [adminActivities, setAdminActivities] = useState<AdminActivityItem[]>([]);
  const [activityVerified, setActivityVerified] = useState(false);
  const [activityError, setActivityError] = useState("");
  const [integrityReport, setIntegrityReport] = useState<IntegrityReport | null>(null);
  const [integrityError, setIntegrityError] = useState("");
  const [labSources, setLabSources] = useState<LabSource[]>([]);
  const [selectedLabSource, setSelectedLabSource] = useState("");
  const [labCopy, setLabCopy] = useState<LabCopy | null>(null);
  const [labStatus, setLabStatus] = useState("");
  const [labError, setLabError] = useState("");

  const clearSessionState = useCallback(() => {
    setRecords([]); setLogs([]); setMetalogs([]); setLogCursor(null); setMetalogCursor(null);
    setLogAction(""); setMetalogAction(""); setLogActions([]); setMetalogActions([]); setSelectedEvidence(null); setEvidenceError("");
    setAdminActivities([]); setActivityVerified(false); setIntegrityReport(null);
    setLabSources([]); setSelectedLabSource(""); setLabCopy(null); setLabStatus(""); setCode("");
    setEditingId(null); setEditingRevision(null); setTitle(""); setContent(""); setNotice("");
    setLogError(""); setMetalogError(""); setActivityError(""); setIntegrityError(""); setLabError("");
  }, []);

  const refresh = useCallback(async () => {
    try {
      const session = await api<{ user: User }>("/api/session");
      setUser(session.user);
      const result = await api<{ records: RecordItem[] }>("/api/records");
      setRecords(result.records);
    } catch (cause) {
      if (cause instanceof Error && "status" in cause && cause.status === 401) { setUser(null); clearSessionState(); }
      else setError(cause instanceof Error ? cause.message : "No se pudieron cargar los registros. Intenta actualizar.");
    } finally {
      setLoading(false);
    }
  }, [clearSessionState]);

  useEffect(() => { void refresh(); }, [refresh]);

  useEffect(() => {
    if (!user || user.role === "USER") return;
    let active = true;
    void api<{ logs: LogItem[]; actions: string[]; nextCursor: number | null }>("/api/logs").then((result) => {
      if (active) { setLogs(result.logs); setLogActions(result.actions); setLogCursor(result.nextCursor); }
    }).catch((cause) => { if (active) setLogError(cause instanceof Error ? cause.message : "No se pudieron cargar los logs."); });
    if (user.role === "AUDITOR") void api<{ metalogs: MetalogItem[]; actions: string[]; nextCursor: number | null }>("/api/metalogs").then((result) => {
      if (active) { setMetalogs(result.metalogs); setMetalogActions(result.actions); setMetalogCursor(result.nextCursor); }
    }).catch((cause) => { if (active) setMetalogError(cause instanceof Error ? cause.message : "No se pudieron cargar los metalogs."); });
    return () => { active = false; };
  }, [user]);

  async function submitAuth(action: "register" | "user") {
    setBusy(true); setError("");
    try {
      await api(`/api/auth/${action}`, { method: "POST", body: JSON.stringify({ name }) });
      clearSessionState();
      setName(""); await refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "No se pudo iniciar sesión."); }
    finally { setBusy(false); }
  }

  async function submitSpecial(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      await api("/api/auth/special", { method: "POST", body: JSON.stringify({ role: specialRole, code }) });
      clearSessionState();
      setCode(""); await refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Acceso denegado."); }
    finally { setBusy(false); }
  }

  async function logout() {
    setBusy(true); setError("");
    try { await api("/api/auth/logout", { method: "POST" }); setUser(null); clearSessionState(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "No se pudo cerrar la sesión."); }
    finally { setBusy(false); }
  }

  async function saveRecord(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    setNotice("");
    try {
      const path = editingId ? `/api/records/${editingId}` : "/api/records";
      await api(path, { method: editingId ? "PATCH" : "POST", body: JSON.stringify({ title, content, ...(editingRevision ? { expectedRevision: editingRevision } : {}) }) });
      setTitle(""); setContent(""); setEditingId(null); setEditingRevision(null);
      const result = await api<{ records: RecordItem[] }>("/api/records"); setRecords(result.records);
      setNotice("Cambio guardado con su evidencia de auditoría.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "No se pudo guardar el registro.");
      if (cause instanceof Error && "status" in cause && cause.status === 409) {
        const result = await api<{ records: RecordItem[] }>("/api/records").catch(() => null);
        if (result) setRecords(result.records);
        setNotice("La lista se actualizó. Tus cambios siguen en el formulario; pulsa Editar para cargar la versión actual antes de reintentarlo.");
      }
    }
    finally { setBusy(false); }
  }

  async function loadLogs(event?: React.FormEvent, before?: number, selectedAction = logAction) {
    event?.preventDefault(); setLogError(""); setHistoryBusy(true);
    try {
      const params = new URLSearchParams();
      if (selectedAction) params.set("action", selectedAction);
      if (before) params.set("before", String(before));
      const result = await api<{ logs: LogItem[]; actions: string[]; nextCursor: number | null }>(`/api/logs?${params}`);
      setLogs((previous) => before ? [...previous, ...result.logs] : result.logs);
      setLogActions(result.actions); setLogCursor(result.nextCursor);
    } catch (cause) { setLogError(cause instanceof Error ? cause.message : "No se pudieron consultar los logs."); }
    finally { setHistoryBusy(false); }
  }

  async function loadMetalogs(event?: React.FormEvent, before?: number, selectedAction = metalogAction) {
    event?.preventDefault(); setMetalogError(""); setHistoryBusy(true);
    try {
      const params = new URLSearchParams();
      if (selectedAction) params.set("action", selectedAction);
      if (before) params.set("before", String(before));
      const result = await api<{ metalogs: MetalogItem[]; actions: string[]; nextCursor: number | null }>(`/api/metalogs?${params}`);
      setMetalogs((previous) => before ? [...previous, ...result.metalogs] : result.metalogs);
      setMetalogActions(result.actions); setMetalogCursor(result.nextCursor);
    } catch (cause) { setMetalogError(cause instanceof Error ? cause.message : "No se pudieron consultar los metalogs."); }
    finally { setHistoryBusy(false); }
  }

  async function saveEvidence(field: string, value: string) {
    if (!selectedEvidence) return;
    setAuditBusy(true); setEvidenceError(""); setNotice("");
    try {
      const { source, event } = selectedEvidence;
      await api(`/api/${source === "LOG" ? "logs" : "metalogs"}/${event.event_id}`, {
        method: "PATCH", body: JSON.stringify({ field, value, expectedRevision: event.edit_revision }),
      });
      setSelectedEvidence(null); setIntegrityReport(null);
      setNotice("Contenido editado. Se conservó la firma original y se generó un metalog con los valores anteriores y nuevos.");
      await loadLogs();
      if (user?.role === "AUDITOR") await loadMetalogs();
    } catch (cause) { setEvidenceError(cause instanceof Error ? cause.message : "No se pudo guardar la edición."); }
    finally { setAuditBusy(false); }
  }

  async function verifyAdminActivity() {
    setActivityError(""); setAdminActivities([]); setActivityVerified(false); setAuditBusy(true);
    try {
      const result = await api<{ activities: AdminActivityItem[] }>("/api/audit/admin-activity");
      setAdminActivities(result.activities);
      setActivityVerified(true);
    } catch (cause) { setActivityError(cause instanceof Error ? cause.message : "No se pudo verificar la actividad administrativa."); }
    finally { setAuditBusy(false); }
  }

  async function verifyIntegrity() {
    setIntegrityError(""); setIntegrityReport(null); setAuditBusy(true);
    try { setIntegrityReport(await api<IntegrityReport>("/api/audit/integrity")); }
    catch (cause) { setIntegrityError(cause instanceof Error ? cause.message : "No se pudo verificar la cadena."); }
    finally { setAuditBusy(false); }
  }

  async function loadLabSources() {
    setLabError("");
    try { const result = await api<{ sources: LabSource[] }>("/api/audit/lab/sources"); setLabSources(result.sources); }
    catch (cause) { setLabError(cause instanceof Error ? cause.message : "No se pudieron cargar eventos."); }
  }

  async function createLabCopy() {
    const [source, eventId] = selectedLabSource.split(":");
    if (!source || !eventId) return;
    setLabError(""); setLabStatus("");
    try {
      const result = await api<{ copy: LabCopy }>("/api/audit/lab/copies", { method: "POST", body: JSON.stringify({ source, eventId }) });
      setLabCopy(result.copy);
    } catch (cause) { setLabError(cause instanceof Error ? cause.message : "No se pudo crear la copia aislada."); }
  }

  async function mutateLabCopy() {
    if (!labCopy) return;
    setLabError("");
    try {
      const result = await api<{ copy: LabCopy }>(`/api/audit/lab/copies/${labCopy.copyId}`, { method: "PATCH", body: JSON.stringify({ field: "action", value: `${String(labCopy.working.action)}_ALTERADA`, expectedRevision: labCopy.revision }) });
      setLabCopy(result.copy); setLabStatus("Campo action modificado solo en la copia.");
    } catch (cause) { setLabError(cause instanceof Error ? cause.message : "No se pudo modificar la copia."); }
  }

  async function verifyLabCopy() {
    if (!labCopy) return;
    setLabError("");
    try {
      const result = await api<{ status: string; contentHashValid: boolean | null; signatureValid: boolean | null }>(`/api/audit/lab/copies/${labCopy.copyId}/verify`, { method: "POST" });
      setLabStatus(`Resultado: ${result.status} · Hash de contenido: ${result.contentHashValid === null ? "no verificable" : result.contentHashValid ? "válido" : "discrepancia"} · HMAC: ${result.signatureValid === null ? "no verificable" : result.signatureValid ? "válido para el hash original" : "inválida"}`);
    } catch (cause) { setLabError(cause instanceof Error ? cause.message : "No se pudo verificar la copia."); }
  }

  async function resetLabCopy() {
    if (!labCopy) return;
    setLabError("");
    try {
      await api(`/api/audit/lab/copies/${labCopy.copyId}`, { method: "DELETE" });
      setLabCopy(null); setLabStatus("Copia aislada reiniciada. La evidencia original permanece intacta.");
    } catch (cause) { setLabError(cause instanceof Error ? cause.message : "No se pudo reiniciar el laboratorio."); }
  }

  function edit(item: RecordItem) { setEditingId(item.id); setEditingRevision(item.revision); setTitle(item.title); setContent(item.content); window.scrollTo({ top: 0, behavior: "smooth" }); }

  if (loading) return <main className="loading">Cargando TraceLab…</main>;

  return (
    <main className="shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="TraceLab inicio"><span className="brand-mark">T</span><span>Trace<span className="brand-light">Lab</span></span></a>
        {user && <div className="profile"><span className="role-chip">{user.role}</span><span className="profile-name">{user.name}</span><button className="quiet-button" onClick={() => void logout()} disabled={busy}>Salir</button></div>}
      </header>

      {!user ? (
        <section className="login-layout">
          <div className="intro">
            <span className="eyebrow"><span className="pulse" /> LABORATORIO DE SEGURIDAD</span>
            <h1>La historia de cada cambio, <em>visible.</em></h1>
            <p>Un espacio educativo para explorar registros, supervisión e integridad digital.</p>
            <div className="intro-rule"><span>01</span><span>Entorno de aprendizaje</span><span className="rule-line" /></div>
          </div>
          <div className="login-card">
            <div className="card-heading"><div><span className="eyebrow">ACCESO AL ENTORNO</span><h2>Bienvenido</h2></div><span className="lock-icon">⌑</span></div>
            <p className="muted">Estudiantes pueden registrarse o ingresar con su nombre.</p>
            <form onSubmit={(event) => { event.preventDefault(); void submitAuth("register"); }}>
              <label htmlFor="user-name">Nombre de usuario</label>
              <input id="user-name" value={name} onChange={(event) => setName(event.target.value)} minLength={2} maxLength={40} autoComplete="username" placeholder="Tu nombre" required />
              <div className="button-row"><button className="primary-button" type="submit" disabled={busy}>Crear cuenta <span>↗</span></button><button className="secondary-button" type="button" disabled={busy || !name.trim()} onClick={() => void submitAuth("user")}>Ingresar</button></div>
            </form>
            <details className="special-access">
              <summary>Acceso de administrador o auditor</summary>
              <form onSubmit={(event) => void submitSpecial(event)}>
                <label htmlFor="special-role">Rol</label>
                <select id="special-role" value={specialRole} onChange={(event) => setSpecialRole(event.target.value as "ADMIN" | "AUDITOR")}><option value="ADMIN">Administrador</option><option value="AUDITOR">Auditor</option></select>
                <label htmlFor="special-code">Código de acceso</label>
                <input id="special-code" maxLength={256} type="password" value={code} onChange={(event) => setCode(event.target.value)} autoComplete="current-password" required />
                <button className="secondary-button full-width" disabled={busy}>Ingresar con rol especial</button>
              </form>
            </details>
            <p className="identity-note">El acceso estudiantil por nombre es una simplificación educativa; no verifica identidad real.</p>
            {error && <p className="error-message" role="alert">{error}</p>}
          </div>
        </section>
      ) : (
        <section className="workspace">
          {user.role === "AUDITOR" && <section className="integrity-panel">
            <div className="form-topline"><div><span className="eyebrow">CADENA DE EVIDENCIAS</span><h2>Integridad criptográfica</h2></div><button className="primary-button verify-button" type="button" disabled={auditBusy} onClick={() => void verifyIntegrity()}>VERIFICAR INTEGRIDAD</button></div>
            <p className="muted">Cada evento firmado enlaza SHA-256 del contenido canónico con el hash previo y una firma HMAC del backend.</p>
            <div className="chain-diagram" aria-label="Encadenamiento de eventos"><span>Evento canónico</span><b>→ SHA-256</b><span>Hash del evento</span><b>→ HMAC + hash previo</b><span>Siguiente evento</span></div>
            <p className="worm-note">WORM simulado en operaciones normales. Excepción educativa: ADMIN y AUDITOR pueden editar contenido de logs; solo AUDITOR edita metalogs. Cada cambio se audita y conserva la firma original. No es WORM físico ni certificado.</p>
            {integrityError && <p className="error-message" role="alert">{integrityError}</p>}
            {integrityReport && <div className="integrity-result" role="status"><p>{integrityReport.status === "INTEGRITY_OK" ? "Verificación completa: contenido, firmas y cadena válidos en la instantánea." : integrityReport.status === "INTEGRITY_FAILED" ? "Se detectaron inconsistencias. Revisa el primer error y conserva las evidencias." : "No se puede afirmar integridad total: existen evidencias sin firma o la verificación es incompleta."}</p><strong className={`integrity-status ${integrityReport.status.toLowerCase().replaceAll("_", "-")}`}>{integrityReport.status}</strong><div className="log-meta"><span>Eventos revisados: {integrityReport.reviewed}</span><span>Logs: {integrityReport.counts.logs}</span><span>Metalog: {integrityReport.counts.metalogs}</span><span>Firmados: {integrityReport.counts.signed}</span><span>Hash de contenido válido: {integrityReport.counts.validContentHashes}</span><span>HMAC válida: {integrityReport.counts.validSignatures}</span><span>Históricos sin firma: {integrityReport.counts.legacy}</span></div>{integrityReport.firstInconsistentEvent && <p>Primer error: secuencia {integrityReport.firstInconsistentEvent.sequence} · {integrityReport.firstInconsistentEvent.code} · {integrityReport.firstInconsistentEvent.event_id}</p>}{integrityReport.errors.length > 0 && <ul>{integrityReport.errors.map((item, index) => <li key={`${item.code}-${index}`}>{item.code}{item.sequence ? ` · secuencia ${item.sequence}` : ""}</li>)}</ul>}</div>}
            <div className="lab-box"><div className="form-topline"><div><span className="eyebrow">COPIA AISLADA · SOLO AUDITOR</span><h3>Laboratorio de manipulación</h3></div><button className="secondary-button" type="button" onClick={() => void loadLabSources()}>Cargar eventos</button></div>
              <div className="lab-controls"><label>Evento fuente<select value={selectedLabSource} onChange={(event) => setSelectedLabSource(event.target.value)}><option value="">Selecciona una evidencia</option>{labSources.map((item) => <option key={`${item.source}:${item.event_id}`} value={`${item.source}:${item.event_id}`}>{item.source} · {item.action} · {item.actor_name} · {item.event_id.slice(0, 8)}</option>)}</select></label><button className="secondary-button" type="button" disabled={!selectedLabSource || Boolean(labCopy)} onClick={() => void createLabCopy()}>Crear copia aislada</button></div>
              {labError && <p className="error-message" role="alert">{labError}</p>}{labStatus && <p className="lab-status" role="status">{labStatus}</p>}
              {labCopy && <><p className="muted">Origen: {labCopy.source} · {labCopy.sourceEventId} · Firma disponible: {labCopy.hasSignature ? "sí" : "no; evento histórico"}</p><div className="lab-columns"><div><h4>Original</h4><pre>{JSON.stringify(labCopy.original, null, 2)}</pre></div><div><h4>Copia de trabajo</h4><pre>{JSON.stringify(labCopy.working, null, 2)}</pre></div></div><div className="lab-controls"><button className="secondary-button" type="button" onClick={() => void mutateLabCopy()}>Simular cambio del campo action</button><button className="primary-button" type="button" onClick={() => void verifyLabCopy()}>Verificar firma de la copia</button><button className="text-button" type="button" onClick={() => void resetLabCopy()}>Reiniciar laboratorio</button></div></>}
            </div>
          </section>}
          <div className="workspace-heading"><div><span className="eyebrow">ESPACIO DE TRABAJO · {user.role}</span><h1>{user.role === "AUDITOR" ? "Consulta de registros" : user.role === "ADMIN" ? "Registros del entorno" : "Registros compartidos"}</h1><p>{user.role === "USER" ? "Los diez registros de demostración son compartidos y editables por los estudiantes. También puedes crear y actualizar tus registros." : user.role === "ADMIN" ? "Consulta y actualiza los registros del entorno." : "Vista de solo lectura de registros y logs operativos."}</p></div><span className="record-count">{String(records.length).padStart(2, "0")} <small>REGISTROS</small></span></div>
          {(user.role === "USER" || (user.role === "ADMIN" && editingId)) && <form className="record-form" onSubmit={(event) => void saveRecord(event)}><div className="form-topline"><h2>{editingId ? "Editar registro" : "Nuevo registro"}</h2>{editingId && <button type="button" className="text-button" onClick={() => { setEditingId(null); setEditingRevision(null); setTitle(""); setContent(""); }}>Cancelar</button>}</div><label htmlFor="record-title">Título</label><input id="record-title" maxLength={120} value={title} onChange={(event) => setTitle(event.target.value)} required /><label htmlFor="record-content">Contenido</label><textarea id="record-content" maxLength={5000} rows={4} value={content} onChange={(event) => setContent(event.target.value)} /><button className="primary-button save-button" disabled={busy}>{editingId ? "Guardar cambios" : "Crear registro"}<span>↗</span></button></form>}
          {error && <p className="error-message" role="alert">{error}</p>}
          {notice && <p className="success-message" role="status">{notice}</p>}<button className="secondary-button" type="button" disabled={busy} onClick={() => void refresh()}>Actualizar registros</button>{records.some((item) => item.is_shared === 1) && <SharedRecords records={records.filter((item) => item.is_shared === 1)} editable={user.role !== "AUDITOR"} onEdit={edit} />}<div className="records-list">{records.length === 0 ? <div className="empty-state"><span>∅</span><h2>Aún no hay registros</h2><p>Los registros que crees aparecerán aquí.</p></div> : records.filter((item) => item.is_shared !== 1).map((item, index) => <article className="record-card" key={item.id}><div className="record-index">{String(index + 1).padStart(2, "0")}</div><div className="record-body"><div className="record-title-row"><h2>{item.title}</h2>{user.role === "ADMIN" || user.role === "USER" ? <button className="text-button" onClick={() => edit(item)}>Editar</button> : null}</div><p>{item.content || <span className="muted">Sin contenido</span>}</p><div className="record-meta"><span>Revisión {item.revision}</span><span>{item.owner_name ?? user.name}{item.is_shared ? " · compartido" : ""}</span><span>Actualizado {new Date(item.updated_at).toLocaleString("es-EC")}</span></div></div></article>)}</div>
          {selectedEvidence && <EvidenceEditor key={selectedEvidence.source + selectedEvidence.event.event_id} source={selectedEvidence.source} event={selectedEvidence.event} onSave={(field, value) => void saveEvidence(field, value)} onCancel={() => setSelectedEvidence(null)} busy={auditBusy} error={evidenceError} />}
          {(user.role === "ADMIN" || user.role === "AUDITOR") && <AuditHistory source="LOG" events={logs} actions={logActions} action={logAction} onAction={(value) => { setLogAction(value); setLogCursor(null); void loadLogs(undefined, undefined, value); }} onRefresh={() => void loadLogs()} onOlder={logCursor === null ? undefined : () => void loadLogs(undefined, logCursor)} onEdit={(event) => { setSelectedEvidence({ source: "LOG", event }); setEvidenceError(""); }} error={logError} busy={historyBusy || auditBusy} />}
          {user.role === "AUDITOR" && <AuditHistory source="METALOG" events={metalogs} actions={metalogActions} action={metalogAction} onAction={(value) => { setMetalogAction(value); setMetalogCursor(null); void loadMetalogs(undefined, undefined, value); }} onRefresh={() => void loadMetalogs()} onOlder={metalogCursor === null ? undefined : () => void loadMetalogs(undefined, metalogCursor)} onEdit={(event) => { setSelectedEvidence({ source: "METALOG", event }); setEvidenceError(""); }} error={metalogError} busy={historyBusy || auditBusy} />}
          {user.role === "AUDITOR" && <section className="activity-panel"><div className="form-topline"><div><span className="eyebrow">SUPERVISIÓN · SOLO LECTURA</span><h2>Actividad administrativa</h2></div><button className="primary-button verify-button" type="button" disabled={auditBusy} onClick={() => void verifyAdminActivity()}>VERIFICAR ACTIVIDAD DEL ADMINISTRADOR</button></div>{activityError && <p className="error-message" role="alert">{activityError}</p>}<div className="log-list">{adminActivities.map((activity) => <article className={`log-card activity-card ${activity.source === "METALOG" ? "activity-metalog" : "activity-log"}`} key={`${activity.source}:${activity.event_id}`}><div className="log-head"><strong>{activity.action}</strong><span className={`log-result result-${activity.result.toLowerCase()}`}>{activity.result}</span></div><div className="log-meta"><span>Fuente: {activity.source === "METALOG" ? "Metalog" : "Log"}</span><span>{activity.actor_name} · ADMIN</span><time>{new Date(activity.occurred_at).toLocaleString("es-EC", { timeZone: "UTC" })} UTC</time><span>{activity.event_id}</span><span>Sesión: {activity.session_id ?? "—"}</span><span>IP: {activity.ip_address ?? "No observada"}</span><span>Recurso: {activity.resource}</span></div>{activity.field_name && <div className="log-change"><span>Campo: {activity.field_name}</span><span>Antes: {activity.old_value ?? "—"}</span><span>Después: {activity.new_value ?? "—"}</span></div>}</article>)}</div>{adminActivities.length === 0 && <p className="muted">{activityVerified ? "No se encontraron eventos administrativos." : "Ejecuta la verificación para consultar la actividad administrativa real."}</p>}</section>}
        </section>
      )}
      <footer><span>TraceLab <span className="brand-light">v1.0</span></span><span>Ingeniería de Seguridad del Software</span></footer>
    </main>
  );
}
