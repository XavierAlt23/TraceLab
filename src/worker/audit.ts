export type ActorRole = "ANONYMOUS" | "USER" | "ADMIN" | "AUDITOR" | "SYSTEM";
export type EventResult = "SUCCESS" | "FAILED" | "DENIED" | "CONFLICT";

export interface AuditEvent {
  actorId: string | null;
  actorName: string;
  actorRole: ActorRole;
  sessionId?: string | null;
  action: string;
  result: EventResult;
  recordId?: string | null;
  fieldName?: string | null;
  oldValue?: string | null;
  newValue?: string | null;
  context?: Record<string, string | number | boolean | null>;
}

export interface AuditActor {
  actorId: string | null;
  actorName: string;
  actorRole: Exclude<ActorRole, "ANONYMOUS" | "SYSTEM">;
  sessionId: string;
}
