import { IngestConfig, Stream } from "@514labs/moose-lib";
import { JobLifecycleEvent } from "../datamodels/JobLifecycleEvent";

// Optional: Configure retention or other ingestion settings here
export const config: IngestConfig<JobLifecycleEvent> = {
    destination: new Stream<JobLifecycleEvent>("JobLifecycleEventStream"),
};
