import { Key } from "@514labs/moose-lib";

export interface MalwareEvent {
  event_id: Key<string>;
  timestamp: Date;
  session_id: string;
  process_name: string;
  pid: number;
  ppid: number;
  action: string;
  target_path: string | null;
  command_line: string | null;
  hashes: string[] | null;
  user_sid: string | null;
  severity: number;
}
