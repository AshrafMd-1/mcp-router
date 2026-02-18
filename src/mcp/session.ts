import { randomUUID } from 'node:crypto';

export interface GatewaySession {
  id: string;
  clientId: string;
  createdAt: number;
  lastSeenAt: number;
}

export class SessionManager {
  private readonly sessions = new Map<string, GatewaySession>();

  create(clientId: string): GatewaySession {
    const id = randomUUID();
    const session: GatewaySession = {
      id,
      clientId,
      createdAt: Date.now(),
      lastSeenAt: Date.now()
    };
    this.sessions.set(id, session);
    return session;
  }

  get(id: string): GatewaySession | null {
    const session = this.sessions.get(id);
    if (!session) return null;
    session.lastSeenAt = Date.now();
    return session;
  }
}
