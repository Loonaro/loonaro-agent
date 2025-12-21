import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createClient } from "@clickhouse/client";

// ClickHouse client configuration
// Using port 18123 as per moose.config.toml (host_port)
const client = createClient({
    url: "http://localhost:18123",
    username: "panda",
    password: "pandapass",
    database: "local",
});

const server = new McpServer({
    name: "loonaro-mcp",
    version: "1.0.0",
});

server.tool(
    "query_telemetry",
    "Query malware telemetry data from ClickHouse",
    {
        limit: z.number().default(10).describe("Max number of events to return"),
        process_name_filter: z.string().optional().describe("Filter by process name"),
    },
    async ({ limit, process_name_filter }) => {
        let query = `SELECT * FROM MalwareEvent_0_0`;
        if (process_name_filter) {
            // Basic SQL injection prevention for demo purposes
            const safeProcessName = process_name_filter.replace(/'/g, "''");
            query += ` WHERE process_name = '${safeProcessName}'`;
        }
        query += ` ORDER BY timestamp DESC LIMIT ${limit}`;

        try {
            const resultSet = await client.query({
                query: query,
                format: "JSONEachRow",
            });
            const data = await resultSet.json();
            return {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(data, null, 2),
                    },
                ],
            };
        } catch (err: any) {
            return {
                content: [
                    {
                        type: "text",
                        text: `Error querying telemetry: ${err.message}`,
                    },
                ],
                isError: true,
            };
        }
    }
);

async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Loonaro MCP Server running on stdio");
}

main().catch((err) => {
    console.error("Server failed to start:", err);
    process.exit(1);
});
