import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { resolve as resolvePath } from "node:path";

import type { TestProcesses } from "../process/processFixture.js";

const LISTENING_MESSAGE = "MCP transport listening";
const STARTUP_TIMEOUT_MS = 30_000;

/** A compiled REA listener child and the URL it announced. */
export interface McpHttpProcess {
  readonly child: ChildProcessWithoutNullStreams;
  readonly url: URL;
  /** The announced `Authorization` header, or none when the listener admits clients without one. */
  readonly headers: Readonly<Record<string, string>>;
  /** Everything the child has written to stderr so far. */
  readonly stderr: () => string;
}

interface Listening {
  readonly url: URL;
  readonly headers: Readonly<Record<string, string>>;
}

/** Find the bound URL and credential in the pino JSON lines the listener writes to stderr. */
const listening = (stderr: string): Listening | undefined => {
  for (const line of stderr.split("\n")) {
    let entry: unknown;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }
    if (
      typeof entry === "object" &&
      entry !== null &&
      "msg" in entry &&
      entry.msg === LISTENING_MESSAGE &&
      "url" in entry &&
      typeof entry.url === "string"
    )
      return {
        url: new URL(entry.url),
        headers:
          "client_credential" in entry &&
          typeof entry.client_credential === "string"
            ? { authorization: `Bearer ${entry.client_credential}` }
            : {},
      };
  }
  return undefined;
};

/** Spawn `rea <arguments>` with stdin closed and resolve once it announces its MCP URL. */
export const startListeningProcess = async (
  processes: TestProcesses,
  arguments_: readonly string[],
  environment: Readonly<Record<string, string>> = {},
): Promise<McpHttpProcess> => {
  const child = processes.spawn(
    process.execPath,
    [resolvePath("scripts/rea.mjs"), ...arguments_],
    {
      env: {
        PATH: process.env.PATH ?? "",
        HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
        ...environment,
      },
    },
  );
  // A closed stdin must not end the listener; only signals do.
  child.stdin.end();
  let stderr = "";
  const announced = await new Promise<Listening>((resolve, reject) => {
    const timer = setTimeout(
      () =>
        reject(
          new Error(
            `No listening line within ${String(STARTUP_TIMEOUT_MS)} ms:\n${stderr}`,
          ),
        ),
      STARTUP_TIMEOUT_MS,
    );
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
      const found = listening(stderr);
      if (found === undefined) return;
      clearTimeout(timer);
      resolve(found);
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      reject(
        new Error(
          `Listener exited early (${String(code)}, ${String(signal)}):\n${stderr}`,
        ),
      );
    });
  });
  return { child, ...announced, stderr: () => stderr };
};

/** Spawn `rea mcp --http --port 0` and resolve once it names its URL. */
export const startMcpHttpProcess = (
  processes: TestProcesses,
  arguments_: readonly string[] = [],
): Promise<McpHttpProcess> =>
  startListeningProcess(processes, [
    "mcp",
    "--http",
    "--port",
    "0",
    ...arguments_,
  ]);
