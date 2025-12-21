
import { Key, DateTime, ClickHouseTTL, OlapTable, ClickHouseEngines } from "@514labs/moose-lib";

export interface JobLifecycleEvent {
    id: Key<string>;
    session_id: string; // Used for correlation
    timestamp: DateTime; // standard Moose DateTime
    status: "CREATED" | "QUEUED" | "SPAWNING" | "RUNNING" | "COMPLETED" | "FAILED";
    details?: string;
    _ttl?: string & ClickHouseTTL<"timestamp + INTERVAL 90 DAY DELETE">; // Column-level TTL marker if needed, or just table config
}

export const JobLifecycleEvents = new OlapTable<JobLifecycleEvent>("JobLifecycleEvents", {
    engine: ClickHouseEngines.MergeTree,
    orderByFields: ["id", "timestamp"],
    ttl: "timestamp + INTERVAL 90 DAY DELETE"
});
