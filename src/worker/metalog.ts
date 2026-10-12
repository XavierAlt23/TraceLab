import type { ActorRole, EventResult } from "./audit";

export interface MetalogEvent {
  actorId: string | null;
  actorName: string;
  actorRole: ActorRole;
  sessionId?: string | null;
  action: string;
  resource: string;
  result: EventResult;
  context?: Record<string, string | number | boolean | null>;
}
