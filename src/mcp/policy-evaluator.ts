import type { ClientPolicy } from '../db/repositories/client-policies.js';

export function globMatch(text: string, pattern: string): boolean {
  const regex = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');

  return new RegExp(`^${regex}$`).test(text);
}

export function isToolAllowed(policy: ClientPolicy, toolName: string, connectorId: string): { allowed: boolean; reason?: string } {
  if (!policy.connectorIds.includes(connectorId)) {
    return { allowed: false, reason: 'CONNECTOR_NOT_SELECTED' };
  }

  for (const pattern of policy.allowedTools) {
    if (globMatch(toolName, pattern)) {
      return { allowed: true };
    }
  }

  return { allowed: false, reason: 'NOT_ALLOWED' };
}
