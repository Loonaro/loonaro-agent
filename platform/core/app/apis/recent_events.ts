import { ConsumptionUtil } from "@514labs/moose-lib";

export interface QueryParams {
    limit: number;
}

export default async function handle(
    { limit = 50 }: QueryParams,
    { client, sql }: ConsumptionUtil
) {
    return client.query(
        sql`SELECT * FROM MalwareEvent_0_0 ORDER BY timestamp DESC LIMIT ${limit}`
    );
}
