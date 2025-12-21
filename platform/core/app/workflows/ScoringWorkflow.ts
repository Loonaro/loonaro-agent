import { Task, Workflow, OlapTable, Key } from "@514labs/moose-lib";

interface WorkflowState {
    id: Key<string>;
    last_run: Date;
    jobs_scored: number;
}

const stateTable = new OlapTable<WorkflowState>("ScoringWorkflowState");

// Consolidated Task: Identify AND Score
export const scoreJobsTask = new Task<null, void>("score-jobs-task", {
    run: async () => {
        try {
            // 1. Identify
            const response = await fetch("http://localhost:4000/consumption/JobStatusView?limit=10&status=COMPLETED");
            if (!response.ok) return;
            const jobs: any[] = await response.json();

            // 2. Trigger Scoring
            for (const job of jobs) {
                console.log(`Triggering scoring for job: ${job.id}`);
                try {
                    const resp = await fetch("http://host.docker.internal:5002/score", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ session_id: job.id })
                    });
                    if (!resp.ok) console.error(`Failed to score ${job.id}: ${resp.statusText}`);
                } catch (e) {
                    console.error(`Error scoring ${job.id}`, e);
                }
            }
        } catch (e) {
            console.error("Workflow failed", e);
        }
    },
    retries: 3
});

export const scoringWorkflow = new Workflow("scoring-workflow", {
    startingTask: scoreJobsTask,
    schedule: "* * * * *",
});
