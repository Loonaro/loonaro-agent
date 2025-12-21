import { createMaterializedView } from "@514labs/moose-lib";
import { FeatureVector } from "../datamodels/FeatureVector";

export const featureVectorView = createMaterializedView({
    name: "FeatureVectorView",
    destinationTable: "FeatureVectors",
    select: `
        SELECT 
            session_id,
            count() as total_events,
            countIf(action = 'FileCreate') as file_creates,
            countIf(action = 'FileWrite') as file_writes,
            countIf(action = 'ProcessCreate') as process_creates,
            countIf(action = 'NetworkConnect') as network_conns,
            countIf(action = 'DNSQuery') as dns_queries,
            uniq(process_name) as unique_processes,
            max(severity) as max_severity,
            sequenceMatch('(?1).*(?2)')(timestamp, action = 'NetworkConnect', action = 'ProcessCreate') as downloader_flow,
            max(timestamp) as last_activity
        FROM MalwareEvent
        GROUP BY session_id
    `
});
