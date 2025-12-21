import { Key } from "@514labs/moose-lib";

export interface FeatureVector {
    session_id: Key<string>;
    total_events: number;
    file_creates: number;
    file_writes: number;
    process_creates: number;
    network_conns: number;
    dns_queries: number;
    unique_processes: number;
    max_severity: number;
    downloader_flow: boolean;
    last_activity: Date;
}
