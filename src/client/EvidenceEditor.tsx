import { useState } from "react";
import { eventTitle, type HistoryEvent } from "./AuditHistory";

export function EvidenceEditor({ source, event, onSave, onCancel, busy, error }: {
  source: "LOG" | "METALOG"; event: HistoryEvent; onSave: (field: string, value: string) => void;
  onCancel: () => void; busy: boolean; error: string;
}) {
  const [field, setField] = useState("actor_name");
  const [value, setValue] = useState(event.actor_name);
  const fields = [{ id: "actor_name", label: "Nombre" }, { id: "ip_address", label: "IP observada" }, { id: "actor_role", label: "Rol registrado" },
    { id: "occurred_at", label: "Fecha y hora UTC" }, { id: "action", label: "Acción" }, { id: "result", label: "Resultado" },
    ...(source === "LOG" ? [{ id: "old_value", label: "Valor anterior" }, { id: "new_value", label: "Valor nuevo" }] : [])];
  return <section id="evidence-editor" className="evidence-editor" role="region" aria-label="Editar evidencia">
    <h3>Editar {eventTitle(event.action)}</h3>
    <p>Excepción educativa: cambia el contenido original y conserva su firma. El cambio genera un metalog; la verificación detectará la alteración.</p>
    <form onSubmit={(submit) => { submit.preventDefault(); onSave(field, value); }}>
      <label>Campo<select value={field} onChange={(change) => { const key = change.target.value; setField(key); setValue(String(event[key as keyof HistoryEvent] ?? "")); }}>{fields.map((item) => <option value={item.id} key={item.id}>{item.label}</option>)}</select></label>
      <label>Valor original<output>{String(event[field as keyof HistoryEvent] ?? "Sin valor")}</output></label>
      <label>Nuevo valor{field === "actor_role" || field === "result" ? <select value={value} onChange={(change) => setValue(change.target.value)}>{(field === "actor_role" ? ["USER", "ADMIN", "AUDITOR", "SYSTEM", "ANONYMOUS"] : ["SUCCESS", "FAILED", "DENIED", "CONFLICT"]).map((item) => <option key={item}>{item}</option>)}</select> : <input value={value} onChange={(change) => setValue(change.target.value)} maxLength={field === "ip_address" ? 64 : ["actor_name", "action"].includes(field) ? 100 : 5000} placeholder={field === "occurred_at" ? "2026-10-12T12:00:00.000Z" : "Nuevo valor"} />}</label>
      {error && <p role="alert" className="error-message">{error}</p>}
      <div className="button-row"><button className="primary-button" disabled={busy}>Guardar edición y metalog</button><button className="secondary-button" type="button" disabled={busy} onClick={onCancel}>Cancelar</button></div>
    </form>
  </section>;
}
