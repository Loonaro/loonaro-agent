"use client";

import { useEffect, useState } from "react";

interface MalwareEvent {
    event_id: string;
    timestamp: string;
    host_id: string;
    process_name: string;
    pid: number;
    action: string;
    target_path: string | null;
    severity: number;
}

export default function Home() {
    const [events, setEvents] = useState<MalwareEvent[]>([]);

    useEffect(() => {
        const fetchEvents = async () => {
            try {
                const res = await fetch("http://localhost:4000/consumption/recent_events?limit=50");
                if (res.ok) {
                    const data = await res.json();
                    setEvents(data);
                }
            } catch (e) {
                console.error("Failed to fetch events", e);
            }
        };

        fetchEvents();
        const interval = setInterval(fetchEvents, 2000);
        return () => clearInterval(interval);
    }, []);

    return (
        <main className="p-8">
            <h1 className="text-3xl font-bold mb-6">Live Malware Analysis Feed</h1>
            <div className="overflow-x-auto">
                <table className="min-w-full bg-white border border-gray-300">
                    <thead>
                        <tr className="bg-gray-100">
                            <th className="py-2 px-4 border-b text-left">Timestamp</th>
                            <th className="py-2 px-4 border-b text-left">Severity</th>
                            <th className="py-2 px-4 border-b text-left">Action</th>
                            <th className="py-2 px-4 border-b text-left">Process</th>
                            <th className="py-2 px-4 border-b text-left">PID</th>
                            <th className="py-2 px-4 border-b text-left">Target Path</th>
                        </tr>
                    </thead>
                    <tbody>
                        {events.map((event) => (
                            <tr
                                key={event.event_id}
                                className={event.severity > 80 ? "bg-red-100" : "hover:bg-gray-50"}
                            >
                                <td className="py-2 px-4 border-b">
                                    {new Date(event.timestamp).toLocaleString()}
                                </td>
                                <td className="py-2 px-4 border-b font-bold">
                                    <span className={event.severity > 80 ? "text-red-600" : "text-gray-900"}>
                                        {event.severity}
                                    </span>
                                </td>
                                <td className="py-2 px-4 border-b">{event.action}</td>
                                <td className="py-2 px-4 border-b">{event.process_name}</td>
                                <td className="py-2 px-4 border-b">{event.pid}</td>
                                <td className="py-2 px-4 border-b truncate max-w-xs" title={event.target_path || ""}>
                                    {event.target_path || "-"}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </main>
    );
}
