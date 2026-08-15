-- 0050: deferred controller rebuild nodes do not block global readiness.
-- Offline or stale nodes recover later through the durable rebuild state
-- machine, but online nodes must still complete credential rotation first.

ALTER TABLE controller_rebuild_nodes
  DROP CONSTRAINT IF EXISTS controller_rebuild_nodes_state_check;

ALTER TABLE controller_rebuild_nodes
  ADD CONSTRAINT controller_rebuild_nodes_state_check CHECK (state IN (
    'awaiting_heartbeat','heartbeat_verified','rotation_pending',
    'credential_activated','draining','deferred','reconciled'
  ));

-- "ready_with_deferred" is deliberately not terminal: the active controller
-- may serve traffic because every unreconciled node is offline, while the
-- durable rebuild remains open and reports the exact deferred count. Only a
-- rebuild with every node reconciled is "succeeded".
ALTER TABLE controller_rebuild_operations
  DROP CONSTRAINT IF EXISTS controller_rebuild_operations_state_check;

ALTER TABLE controller_rebuild_operations
  ADD CONSTRAINT controller_rebuild_operations_state_check CHECK (state IN (
    'reconciling','ready_with_deferred','succeeded','failed'
  ));

DROP INDEX IF EXISTS idx_controller_rebuild_open;
CREATE INDEX idx_controller_rebuild_open
  ON controller_rebuild_operations (state,updated_at)
  WHERE state IN ('reconciling','ready_with_deferred');

-- Restore the generation fence before reopening an in-flight rebuild. Older
-- controller versions could promote a new epoch without first quarantining
-- nodes that were still published online under the previous epoch. Keeping
-- those rows online would let them remain eligible for scheduling until their
-- next heartbeat, even though that heartbeat must be treated as recovery-only.
UPDATE nodes node
SET status='offline',connectivity_state='offline',capacity_state='unknown',
  capacity_reason_code='controller_generation_stale',
  capacity_pressure_since=NULL,capacity_recovery_since=NULL,
  capacity_cooldown_until=NULL,capacity_changed_at=now()
FROM controller_epochs epoch
WHERE epoch.state='active'
  AND node.connectivity_state='online'
  AND node.controller_generation<>epoch.generation;

-- Upgrade an in-flight rebuild atomically. Nodes which were already offline
-- before this migration cannot produce the heartbeat that the old state
-- machine awaited, so keeping them in awaiting_heartbeat would wedge global
-- readiness forever.
UPDATE controller_rebuild_nodes item
SET state='deferred',updated_at=now()
FROM controller_rebuild_operations rebuild,controller_epochs epoch,nodes node
WHERE item.rebuild_id=rebuild.id AND item.node_id=node.id
  AND rebuild.generation=epoch.generation AND epoch.state='active'
  AND rebuild.state IN ('reconciling','ready_with_deferred')
  AND item.state NOT IN ('deferred','reconciled')
  AND node.connectivity_state<>'online';

WITH progress AS (
  SELECT rebuild.id,
    count(item.node_id)::int AS total_nodes,
    count(item.node_id) FILTER (WHERE item.state='reconciled')::int AS reconciled_nodes,
    count(item.node_id) FILTER (WHERE item.state IN ('reconciled','deferred'))::int AS ready_nodes
  FROM controller_rebuild_operations rebuild
  JOIN controller_epochs epoch ON epoch.generation=rebuild.generation AND epoch.state='active'
  LEFT JOIN controller_rebuild_nodes item ON item.rebuild_id=rebuild.id
  WHERE rebuild.state IN ('reconciling','ready_with_deferred')
  GROUP BY rebuild.id
)
UPDATE controller_rebuild_operations rebuild
SET total_nodes=progress.total_nodes,
  reconciled_nodes=progress.reconciled_nodes,
  state=CASE
    WHEN progress.total_nodes=progress.reconciled_nodes THEN 'succeeded'
    WHEN progress.total_nodes=progress.ready_nodes THEN 'ready_with_deferred'
    ELSE 'reconciling' END,
  completed_at=CASE
    WHEN progress.total_nodes=progress.reconciled_nodes THEN COALESCE(rebuild.completed_at,now())
    ELSE NULL END,
  updated_at=now()
FROM progress
WHERE rebuild.id=progress.id;
