export class CoordinatorElection {
  constructor(options = {}) {
    this.nodeId = String(options.nodeId || '');
    this.term = Number(options.term || 0);
    this.votedFor = options.votedFor || null;
    this.leaderId = options.leaderId || null;
    this.leaseUntil = Number(options.leaseUntil || 0);
    this.snapshotRevision = Number(options.snapshotRevision || 0);
  }

  observeCluster(cluster = {}) {
    const term = Number(cluster.term || 0);
    if (term < this.term) {
      this.snapshotRevision = Math.max(this.snapshotRevision, Number(cluster.revision || 0));
      return this.snapshot();
    }
    if (term > this.term) {
      this.term = term;
      this.votedFor = null;
    }
    if (cluster.coordinatorNodeId) this.leaderId = cluster.coordinatorNodeId;
    this.snapshotRevision = Math.max(this.snapshotRevision, Number(cluster.revision || 0));
    return this.snapshot();
  }

  noteLeader({ term, leaderId, revision, leaseMs = 12_000 }, now = Date.now()) {
    const nextTerm = Number(term || 0);
    const nextLeader = String(leaderId || '');
    if (nextTerm < this.term) {
      if (this.leaseUntil > now && this.leaderId) {
        return { accepted: false, term: this.term, reason: 'stale-term' };
      }
      if (!nextLeader) return { accepted: false, term: this.term, reason: 'stale-term' };
      return this.followLease({ term: nextTerm, leaderId: nextLeader, revision, leaseMs }, now);
    }
    if (nextTerm === this.term && this.leaseUntil > now && this.leaderId && this.leaderId !== String(leaderId || '')) {
      return { accepted: false, term: this.term, reason: 'conflicting-leader' };
    }
    if (nextTerm > this.term) this.votedFor = null;
    this.term = nextTerm;
    this.leaderId = String(leaderId || '');
    this.snapshotRevision = Math.max(this.snapshotRevision, Number(revision || 0));
    this.leaseUntil = now + Math.max(1_000, Number(leaseMs || 12_000));
    return { accepted: true, term: this.term, revision: this.snapshotRevision };
  }

  requestVote({ term, candidateId, revision }, now = Date.now()) {
    const nextTerm = Number(term || 0);
    const candidate = String(candidateId || '');
    const candidateRevision = Number(revision || 0);
    if (!candidate || nextTerm < this.term) return { granted: false, term: this.term, reason: 'stale-term' };
    if (this.leaseUntil > now && this.leaderId && this.leaderId !== candidate) {
      return { granted: false, term: this.term, reason: 'leader-lease-active' };
    }
    if (candidateRevision < this.snapshotRevision) {
      return { granted: false, term: this.term, reason: 'snapshot-behind', revision: this.snapshotRevision };
    }
    if (nextTerm > this.term) {
      this.term = nextTerm;
      this.votedFor = null;
      this.leaderId = null;
      this.leaseUntil = 0;
    }
    if (this.votedFor && this.votedFor !== candidate) {
      return { granted: false, term: this.term, reason: 'already-voted' };
    }
    this.votedFor = candidate;
    return { granted: true, term: this.term, revision: this.snapshotRevision };
  }

  beginElection() {
    this.term += 1;
    this.votedFor = this.nodeId;
    this.leaderId = null;
    this.leaseUntil = 0;
    return { term: this.term, candidateId: this.nodeId, revision: this.snapshotRevision };
  }

  followLease({ term, leaderId, revision, leaseMs = 12_000 }, now = Date.now()) {
    const leader = String(leaderId || '');
    if (!leader) return { accepted: false, term: this.term };
    this.term = Math.max(0, Number(term || 0));
    this.votedFor = leader;
    this.leaderId = leader;
    this.snapshotRevision = Math.max(this.snapshotRevision, Number(revision || 0));
    this.leaseUntil = now + Math.max(1_000, Number(leaseMs || 12_000));
    return { accepted: true, term: this.term, leaderId: leader };
  }

  quorum(voterCount) {
    return Math.floor(Math.max(1, Number(voterCount || 1)) / 2) + 1;
  }

  snapshot() {
    return {
      term: this.term,
      votedFor: this.votedFor,
      leaderId: this.leaderId,
      leaseUntil: this.leaseUntil,
      snapshotRevision: this.snapshotRevision,
    };
  }
}
