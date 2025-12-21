
import { createMaterializedView } from "@514labs/moose-lib";
import { JobStatuses } from "../datamodels/JobStatus";

// The source table name in ClickHouse usually matches the Stream name or Ingestion API name.
// Assuming "JobLifecycleEventStream" maps to a ClickHouse table (managed by Moose).
// If Moose creates a table for the stream, it's typically named after the stream + "_stream" suffix or just the stream name.
// Let's assume standardized naming: JobLifecycleEventStream -> JobLifecycleEventStream

/* 
 * Standard SQL Aggregation:
 * We select the fields from the stream and insert them into the ReplacingMergeTree table.
 * The ReplacingMergeTree engine handles the deduplication on 'id' using 'last_updated'.
 */

export const jobStatusView = createMaterializedView({
    name: "JobStatusView",
    destinationTable: "JobStatuses",
    select: `
        SELECT 
            session_id as id,
            status,
            timestamp as event_time,
            details
        FROM JobLifecycleEventStream
        WHERE session_id != ''
    `
});
