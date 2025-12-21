import { Key } from "@514labs/moose-lib";

export interface AnalysisReport {
    session_id: Key<string>;
    score: number;
    verdict: string; // "Benign", "Suspicious", "Malicious"
    triggered_rules: string[]; // JSON array of rule names
    timestamp: Date;
}
