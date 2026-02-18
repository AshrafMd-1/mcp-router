import { describe, expect, it } from 'vitest';
import { globMatch, isToolAllowed } from '../src/mcp/policy-evaluator.js';

describe('globMatch', () => {
  it('matches wildcard patterns', () => {
    expect(globMatch('linear.create_issue', 'linear.*')).toBe(true);
    expect(globMatch('linear.delete_issue', 'linear.delete_*')).toBe(true);
    expect(globMatch('github.list_repos', 'linear.*')).toBe(false);
  });
});

describe('isToolAllowed', () => {
  const policy = {
    id: 'p1',
    clientId: 'c1',
    connectorIds: ['connector-1'],
    allowedTools: ['linear.*'],
    deniedTools: [],
    updatedAt: new Date().toISOString()
  };

  it('denies if connector not selected', () => {
    const d = isToolAllowed(policy, 'linear.create_issue', 'connector-2');
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe('CONNECTOR_NOT_SELECTED');
  });

  it('allows explicit allow', () => {
    const d = isToolAllowed(policy, 'linear.create_issue', 'connector-1');
    expect(d.allowed).toBe(true);
  });

  it('allows wildcard-matching tool', () => {
    const d = isToolAllowed(policy, 'linear.delete_issue', 'connector-1');
    expect(d.allowed).toBe(true);
  });
});
