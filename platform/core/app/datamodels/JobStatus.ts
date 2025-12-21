
import { Key, DateTime, OlapTable, ClickHouseEngines } from "@514labs/moose-lib";

export interface JobStatus {
    id: Key<string>; // This maps to session_id
    status: string;
    last_updated: DateTime;
    details?: string;
}

export const JobStatuses = new OlapTable<JobStatus>("JobStatuses", {
    engine: ClickHouseEngines.ReplacingMergeTree,
    orderByFields: ["id"], // Dedup by ID (session_id)
    ver: "last_updated" // Keep the row with the latest timestamp
});
