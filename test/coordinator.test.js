import test from 'node:test';
import assert from 'node:assert/strict';
import { CoordinatorElection } from '../src/core/coordinator.js';

test('协调选举拒绝旧快照、重复投票和有效租约期间的候选者', () => {
  const election = new CoordinatorElection({ nodeId: 'node-b', term: 4, leaderId: 'node-a', leaseUntil: 20_000, snapshotRevision: 12 });
  assert.equal(election.requestVote({ term: 5, candidateId: 'node-c', revision: 12 }, 10_000).reason, 'leader-lease-active');
  assert.equal(election.requestVote({ term: 5, candidateId: 'node-c', revision: 11 }, 21_000).reason, 'snapshot-behind');
  assert.equal(election.requestVote({ term: 5, candidateId: 'node-c', revision: 12 }, 21_000).granted, true);
  assert.equal(election.requestVote({ term: 5, candidateId: 'node-d', revision: 13 }, 21_001).reason, 'already-voted');
});

test('候选者递增任期并按多数节点计算安全法定票数', () => {
  const election = new CoordinatorElection({ nodeId: 'node-b', term: 2, snapshotRevision: 9 });
  assert.deepEqual(election.beginElection(), { term: 3, candidateId: 'node-b', revision: 9 });
  assert.equal(election.quorum(1), 1);
  assert.equal(election.quorum(3), 2);
  assert.equal(election.quorum(4), 3);
  assert.equal(election.noteLeader({ term: 3, leaderId: 'node-b', revision: 10 }, 1000).accepted, true);
  assert.equal(election.snapshot().leaseUntil, 13_000);
});

test('旧配置和同任期的第二个领导者不能覆盖当前有效租约', () => {
  const election = new CoordinatorElection({ nodeId: 'node-b', term: 7, leaderId: 'node-a', leaseUntil: 20_000, snapshotRevision: 8 });
  election.observeCluster({ term: 6, coordinatorNodeId: 'node-old', revision: 9 });
  assert.equal(election.leaderId, 'node-a');
  assert.equal(election.snapshotRevision, 9);
  assert.equal(election.noteLeader({ term: 7, leaderId: 'node-c', revision: 10 }, 10_000).reason, 'conflicting-leader');
  assert.equal(election.leaderId, 'node-a');
});

test('碰到已有多数派租约时放弃尚未获胜的本地选举轮次', () => {
  const election = new CoordinatorElection({ nodeId: 'node-c', term: 9, votedFor: 'node-c' });
  const result = election.followLease({ term: 4, leaderId: 'node-b', revision: 12, leaseMs: 2_000 }, 1_000);
  assert.equal(result.accepted, true);
  assert.equal(election.term, 4);
  assert.equal(election.leaderId, 'node-b');
  assert.equal(election.leaseUntil, 3_000);
});
