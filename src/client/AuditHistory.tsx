export interface HistoryEvent {
  event_id: string; sequence: number; actor_name: string; actor_role: string;
  session_id: string | null; occurred_at: string; ip_address: string | null; user_agent: string | null;
  action: string; result: string; context_json?: string | null; record_id?: string | null;
  field_name?: string | null; old_value?: string | null; new_value?: string | null; resource?: string;
  edit_revision: number;
}

const titles: Record<string, string> = {
  "record.list": "Visualizó registros", "record.update": "Editó un registro", "record.create": "Creó un registro",
  "user.create": "Creó una cuenta", "auth.login": "Ingresó al sistema", "auth.logout": "Cerró sesión",
  "auth.privileged_login": "Intentó ingresar con rol especial", "access.denied": "Acceso denegado",
  "logs.access": "Intentó acceder a logs", "metalog.access": "Intentó acceder a metalogs",
  ADMIN_LOGS_VIEWED: "Administrador consultó logs", AUDITOR_LOGS_VIEWED: "Auditor consultó logs",
  ADMIN_METALOG_ACCESS_DENIED: "Administrador intentó consultar metalogs", AUDITOR_METALOGS_VIEWED: "Auditor consultó metalogs",
  ADMIN_ACTIVITY_VERIFIED: "Verificó actividad del administrador", ACCESS_DENIED: "Acceso denegado",
  INTEGRITY_VERIFICATION: "Verificó integridad", EVIDENCE_CONTENT_EDITED: "Editó una evidencia original",
  LAB_COPY_CREATED: "Creó una copia de laboratorio", LAB_TAMPER_SIMULATED: "Editó una copia de laboratorio",
  LAB_COPY_VERIFIED: "Verificó una copia", LAB_RESET: "Reinició el laboratorio",
};
export const eventTitle = (action: string) => titles[action] ?? action.replaceAll("_", " ");

export function AuditHistory({ source, events, actions, action, onAction, onRefresh, onOlder, onEdit, error, busy }: {
  source: "LOG" | "METALOG"; events: HistoryEvent[]; actions: string[]; action: string;
  onAction: (value: string) => void; onRefresh: () => void; onOlder?: () => void;
  onEdit?: (event: HistoryEvent) => void; error: string; busy: boolean;
}) {
  const label = source === "LOG" ? "Logs de trazabilidad" : "Metalogs de supervisión";
  return <section className={`history-panel ${source === "METALOG" ? "history-metalogs" : ""}`} aria-label={label}>
    <div className="history-heading"><div><span className="eyebrow">{source === "LOG" ? "ACTIVIDAD DEL SISTEMA" : "AUDITORÍA Y SUPERVISIÓN"}</span><h2>{label}</h2><p>Eventos reales · Más recientes primero</p></div><button className="secondary-button" disabled={busy} onClick={onRefresh}>Actualizar {source === "LOG" ? "logs" : "metalogs"}</button></div>
    <div className="history-filter"><label>Título del {source === "LOG" ? "log" : "metalog"}<select value={action} disabled={busy} onChange={(event) => onAction(event.target.value)}><option value="">Todos los títulos</option>{actions.map((value) => <option value={value} key={value}>{eventTitle(value)}</option>)}</select></label><span>{events.length} eventos mostrados</span></div>
    {error && <p role="alert" className="error-message">{error}</p>}
    <div className="history-list">{events.map((event) => {
      const time = new Date(event.occurred_at);
      return <article className="history-event" key={event.event_id}>
        <div className="history-event-heading"><div><small>#{event.sequence} · {source === "LOG" ? "LOG" : "METALOG"}</small><h3>{eventTitle(event.action)}</h3></div><span className={`history-result result-${event.result.toLowerCase()}`}>{({ SUCCESS: "Exitoso", FAILED: "Fallido", DENIED: "Denegado", CONFLICT: "Conflicto" } as Record<string, string>)[event.result] ?? event.result}</span></div>
        <dl className="history-metadata"><div><dt>Nombre</dt><dd>{event.actor_name}</dd></div><div><dt>Rol</dt><dd>{event.actor_role}</dd></div><div><dt>Fecha UTC</dt><dd>{time.toISOString().slice(0, 10)}</dd></div><div><dt>Hora UTC</dt><dd>{time.toISOString().slice(11, 19)}</dd></div><div><dt>IP observada</dt><dd>{event.ip_address ?? "No observada"}</dd></div><div><dt>MAC</dt><dd>No disponible en navegador</dd></div></dl>
        {event.field_name && <div className="history-change"><strong>Campo: {event.field_name === "title" ? "Título" : event.field_name === "content" ? "Contenido" : event.field_name}</strong><div><span>Antes</span><p>{event.old_value ?? "Sin valor"}</p></div><div><span>Después</span><p>{event.new_value ?? "Sin valor"}</p></div></div>}
        {event.edit_revision > 0 && <p className="history-altered">Contenido editado · Firma original conservada · Verifica integridad para detectar la alteración</p>}
        <details className="event-details"><summary>Detalle del evento</summary><dl><dt>ID</dt><dd>{event.event_id}</dd><dt>Sesión no secreta</dt><dd>{event.session_id ?? "No disponible"}</dd><dt>Acción</dt><dd>{event.action}</dd><dt>{source === "LOG" ? "Registro" : "Recurso"}</dt><dd>{event.record_id ?? event.resource ?? "No aplica"}</dd><dt>User-Agent</dt><dd>{event.user_agent ?? "No observado"}</dd></dl>{event.context_json && <pre>{event.context_json}</pre>}</details>
        {onEdit && <button className="secondary-button history-edit" onClick={() => onEdit(event)}>Editar contenido del {source === "LOG" ? "log" : "metalog"}</button>}
      </article>;
    })}</div>
    {!events.length && <p className="history-empty">No hay eventos para este título. Las actividades que realices aparecerán aquí.</p>}
    {onOlder && <button className="secondary-button" disabled={busy} onClick={onOlder}>Ver eventos anteriores</button>}
  </section>;
}
