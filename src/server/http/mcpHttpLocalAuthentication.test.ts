import { execFileSync, spawn, spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { Agent, request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import {
  Client,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import pino from "pino";
import { afterEach, expect, it } from "vitest";
import { z } from "zod";

import { GdbSessionManager } from "../../gdb/GdbSessionManager.js";
import { silentLogger } from "../../logger.js";
import { registerGdbTools } from "../registerGdbTools.js";
import { RequestTrackingMcpServer } from "../RequestTrackingMcpServer.js";
import { createToolResultDelivery } from "../toolResult.js";
import { rawHttpRequest } from "../../../tests/support/http/rawRequest.js";
import {
  serveStreamableHttp,
  type StreamableHttpServer,
} from "./serveStreamableHttp.js";

/**
 * Spec for the streamable HTTP listener: another local account that can see
 * the bound port must not open a session, replace one, or run a tool until it
 * presents the per-process credential from the operator channel.
 *
 * The operator channel is the `MCP transport listening` log record: a
 * `client_credential` string, a credential query value on `url`, or
 * `client_credential_path` pointing at a mode 0600 file in a mode 0700
 * directory. The credential is 32 bytes, encoded as 64 lowercase hex
 * characters or 43 unpadded base64url characters. Requests present it as
 * `Authorization: Bearer <credential>`. An equal-length mismatch is compared
 * with `node:crypto` `timingSafeEqual` before Host and Origin checks and
 * before any session or route work. These tests leave Frida, rizin, Cutter,
 * and objdump uninvoked; those tools share this admission gate.
 */

const STREAMABLE_ACCEPT = "application/json, text/event-stream";
const CREDENTIAL_TEXT = /^(?:[0-9a-f]{64}|[A-Za-z0-9_-]{43})$/u;
const SHELL_PROBE = "rea-http-auth-probe";
const NOBODY_UID = Number(
  execFileSync("id", ["-u", "nobody"], { encoding: "utf8" }).trim(),
);

const servers: StreamableHttpServer[] = [];
const managers: GdbSessionManager[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(managers.splice(0).map((manager) => manager.closeAll()));
  await Promise.all(servers.splice(0).map((server) => server.close()));
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

const initializeBody = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "local-peer", version: "1" },
  },
});

const toolCallBody = (
  id: number,
  name: string,
  arguments_: Record<string, unknown>,
): string =>
  JSON.stringify({
    jsonrpc: "2.0",
    id,
    method: "tools/call",
    params: { name, arguments: arguments_ },
  });

interface ListeningRecord {
  readonly [key: string]: unknown;
}

const listeningRecords = (lines: readonly string[]): ListeningRecord[] =>
  lines.flatMap((line) => {
    try {
      const parsed = JSON.parse(line) as ListeningRecord;
      return parsed.msg === "MCP transport listening" ? [parsed] : [];
    } catch {
      return [];
    }
  });

const credentialFromText = (value: string): string | undefined => {
  const trimmed = value.trim();
  return CREDENTIAL_TEXT.test(trimmed) ? trimmed : undefined;
};

/** Operator credential from the listening announcement, never from the attacker. */
const operatorCredential = async (
  lines: readonly string[],
): Promise<string | undefined> => {
  for (const record of listeningRecords(lines)) {
    const named = record.client_credential;
    if (typeof named === "string") {
      const credential = credentialFromText(named);
      if (credential !== undefined) return credential;
    }
    const path = record.client_credential_path;
    if (typeof path === "string") {
      const file = await stat(path);
      const directory = await stat(join(path, ".."));
      if ((file.mode & 0o777) !== 0o600) return undefined;
      if ((directory.mode & 0o777) !== 0o700) return undefined;
      const credential = credentialFromText(await readFile(path, "utf8"));
      if (credential === undefined) return undefined;
      const probe = spawnSync(
        "sudo",
        [
          "-n",
          "-u",
          "nobody",
          "/usr/bin/python3",
          "-c",
          "import pathlib,sys; pathlib.Path(sys.argv[1]).read_text()",
          path,
        ],
        { encoding: "utf8" },
      );
      if (probe.status === 0) return undefined;
      return credential;
    }
    const url = record.url;
    if (typeof url === "string") {
      try {
        const parsed = new URL(url);
        for (const value of parsed.searchParams.values()) {
          const credential = credentialFromText(value);
          if (credential !== undefined) return credential;
        }
      } catch {
        // The listening record's url is not the credential carrier.
      }
    }
    for (const value of Object.values(record)) {
      if (typeof value !== "string") continue;
      const credential = credentialFromText(value);
      if (credential !== undefined) return credential;
    }
  }
  return undefined;
};

const streamableHeaders = (
  extra: Record<string, string> = {},
): Record<string, string> => ({
  accept: STREAMABLE_ACCEPT,
  "content-type": "application/json",
  ...extra,
});

const postJson = (
  url: URL,
  body: string,
  headers: Record<string, string> = {},
) =>
  rawHttpRequest(url, {
    method: "POST",
    headers: streamableHeaders(headers),
    body,
  });

interface StartedListener {
  readonly served: StreamableHttpServer;
  readonly lines: string[];
  readonly marker: string;
  readonly routeHits: { count: number };
  readonly toolHits: { count: number };
}

const gdbStub = (marker: string): string => `#!${process.execPath}
import { appendFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
const marker = ${JSON.stringify(marker)};
const note = (line) => appendFileSync(marker, line + "\\n");
note("spawned uid=" + process.getuid());
process.stdout.write("(gdb)\\n");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const boundary = input.indexOf("\\n");
    if (boundary < 0) break;
    const line = input.slice(0, boundary);
    input = input.slice(boundary + 1);
    note("stdin " + line);
    const match = /^(\\d+)/.exec(line);
    if (!match) continue;
    if (line.includes("list-thread-groups")) {
      process.stdout.write(match[1] + "^done,groups=[]\\n(gdb)\\n");
      continue;
    }
    const shell = /-interpreter-exec console "(.*)"\\s*$/.exec(line);
    if (shell && shell[1].startsWith("shell ")) {
      const ran = spawnSync("/bin/sh", ["-c", shell[1].slice("shell ".length)], {
        encoding: "utf8",
      });
      note("shell-status=" + String(ran.status) + " stdout=" + JSON.stringify(ran.stdout));
    }
    process.stdout.write(match[1] + "^done\\n(gdb)\\n");
  }
});
`;

const startListener = async (host = "127.0.0.1"): Promise<StartedListener> => {
  const directory = await mkdtemp(join(tmpdir(), "rea-http-auth-"));
  directories.push(directory);
  const marker = join(directory, "gdb-marker");
  const provider = join(directory, "fake-gdb.mjs");
  await writeFile(provider, gdbStub(marker));
  await chmod(provider, 0o700);
  const lines: string[] = [];
  const logger = pino(
    { level: "debug" },
    { write: (line) => lines.push(line) },
  );
  const routeHits = { count: 0 };
  const toolHits = { count: 0 };
  const manager = new GdbSessionManager({
    platform: "linux",
    environment: { REA_GDB_COMMAND: provider, REA_GDB_MARKER: marker },
  });
  managers.push(manager);
  const served = await serveStreamableHttp({
    host,
    port: 0,
    logger,
    routes: [
      {
        method: "POST",
        path: "/agentenv",
        handle: () => {
          routeHits.count += 1;
          return new Response("ran");
        },
      },
    ],
    createMcpServer: () => {
      const server = new RequestTrackingMcpServer({
        name: "http-auth-fixture",
        version: "1",
      });
      server.registerTool(
        "echo",
        {
          description: "Echo text",
          inputSchema: z.object({ text: z.string() }),
        },
        ({ text }) => {
          toolHits.count += 1;
          return { content: [{ type: "text", text }] };
        },
      );
      registerGdbTools(
        server,
        manager,
        silentLogger,
        createToolResultDelivery(undefined),
      );
      return server;
    },
  });
  servers.push(served);
  return { served, lines, marker, routeHits, toolHits };
};

interface AttackStep {
  readonly name: string;
  readonly status: number;
}

interface AttackReport {
  readonly attackerUid: number;
  readonly steps: readonly AttackStep[];
  readonly sessionHeaderIssued: boolean;
}

const ATTACK_SCRIPT = String.raw`import json, os, re, socket, sys
port = int(sys.argv[1])
host_header = sys.argv[2]
address = sys.argv[3]
shell_probe = sys.argv[4]

def exchange(method, path, body=None, session=""):
    sock = socket.create_connection((address, port), 5)
    sock.settimeout(5)
    head = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host_header}",
        "Connection: close",
    ]
    if method == "POST":
        head.append("Accept: application/json, text/event-stream")
        head.append("Content-Type: application/json")
    elif method == "GET":
        head.append("Accept: text/event-stream")
    if session:
        head.append(f"mcp-session-id: {session}")
    payload = b"" if body is None else body.encode()
    if body is not None:
        head.append(f"Content-Length: {len(payload)}")
    request = ("\r\n".join(head) + "\r\n\r\n").encode() + payload
    sock.sendall(request)
    data = b""
    while b"\r\n\r\n" not in data:
        try:
            chunk = sock.recv(65536)
        except TimeoutError:
            print("TIMEOUT", method, path, "sent", len(request), "got", len(data), flush=True)
            raise
        if not chunk:
            break
        data += chunk
    head_bytes, _, rest = data.partition(b"\r\n\r\n")
    lowered = head_bytes.lower()
    if method != "GET" and b"text/event-stream" in lowered:
        while b"\n\n" not in rest and b"\r\n\r\n" not in rest:
            chunk = sock.recv(65536)
            if not chunk:
                break
            rest += chunk
    elif b"content-length:" in lowered:
        length = 0
        for line in head_bytes.split(b"\r\n"):
            name, separator, value = line.partition(b":")
            if separator and name.lower() == b"content-length":
                length = int(value.strip())
        while len(rest) < length:
            chunk = sock.recv(65536)
            if not chunk:
                break
            rest += chunk
    sock.close()
    data = head_bytes + b"\r\n\r\n" + rest
    text = data.decode("utf-8", "replace")
    status_line = text.split("\r\n", 1)[0]
    status = int(status_line.split(" ")[1]) if status_line.startswith("HTTP/") else 0
    header_blob = text.split("\r\n\r\n", 1)[0]
    session_id = ""
    for line in header_blob.split("\r\n")[1:]:
        name, separator, value = line.partition(":")
        if separator and name.lower() == "mcp-session-id":
            session_id = value.strip()
    return status, session_id, text

def body(identifier, method, params):
    return json.dumps({
        "jsonrpc": "2.0",
        "id": identifier,
        "method": method,
        "params": params,
    })

steps = []
status, session, text = exchange("POST", "/mcp", body(1, "initialize", {
    "protocolVersion": "2025-11-25",
    "capabilities": {},
    "clientInfo": {"name": "other-account", "version": "1"},
}))
steps.append({"name": "initialize", "status": status})
session_header = bool(session)
listed, _, _ = exchange("POST", "/mcp", body(2, "tools/list", {}), session)
steps.append({"name": "tools/list", "status": listed})
started, _, started_text = exchange("POST", "/mcp", body(3, "tools/call", {
    "name": "start_gdb_session",
    "arguments": {},
}), session)
steps.append({"name": "start_gdb_session", "status": started})
found_session = re.search(r'"session_id"\s*:\s*"([0-9a-f-]{36})"', started_text)
gdb_session = found_session.group(1) if found_session else ""
console, _, _ = exchange("POST", "/mcp", body(4, "tools/call", {
    "name": "gdb_console",
    "arguments": {
        "session_id": gdb_session or "00000000-0000-4000-8000-000000000000",
        "command": "shell printf " + shell_probe,
        "detail": "complete",
    },
}), session)
steps.append({"name": "gdb_console", "status": console})
get_status, _, _ = exchange("GET", "/mcp", None, session)
steps.append({"name": "GET /mcp", "status": get_status})
deleted, _, _ = exchange("DELETE", "/mcp", None, session)
steps.append({"name": "DELETE /mcp", "status": deleted})
route, _, _ = exchange("POST", "/agentenv", "{}")
steps.append({"name": "POST /agentenv", "status": route})
print(json.dumps({
    "attackerUid": os.getuid(),
    "sessionHeaderIssued": session_header,
    "steps": steps,
}))
`;

const attackAsNobody = (
  port: number,
  hostHeader: string,
  address: string,
): Promise<AttackReport> =>
  new Promise((resolve, reject) => {
    // The listener shares this process's event loop, so the client must be
    // asynchronous or the server cannot answer it.
    const child = spawn(
      "sudo",
      [
        "-n",
        "-u",
        "nobody",
        "/usr/bin/python3",
        "-",
        String(port),
        hostHeader,
        address,
        SHELL_PROBE,
      ],
      { stdio: ["pipe", "pipe", "pipe"] },
    );
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`other-account request timed out: ${stderr}`));
    }, 30_000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.once("error", (cause) => {
      clearTimeout(timer);
      reject(cause);
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(
          new Error(
            `other-account request failed (${String(code)}): ${stderr}`,
          ),
        );
        return;
      }
      resolve(JSON.parse(stdout) as AttackReport);
    });
    child.stdin.end(ATTACK_SCRIPT);
  });

const markerText = async (marker: string): Promise<string> => {
  try {
    return await readFile(marker, "utf8");
  } catch (cause) {
    if (
      typeof cause === "object" &&
      cause !== null &&
      "code" in cause &&
      cause.code === "ENOENT"
    )
      return "";
    throw cause;
  }
};

const portListedInProcNetTcp = async (port: number): Promise<boolean> => {
  const info = await stat("/proc/net/tcp");
  expect(info.mode & 0o004).not.toBe(0);
  const table = await readFile("/proc/net/tcp", "utf8");
  return table.includes(`:${port.toString(16).toUpperCase().padStart(4, "0")}`);
};

it("rejects another local account before a session, route, or GDB shell command", async () => {
  const started = await startListener();
  const url = new URL(started.served.url);
  const port = Number(url.port);
  expect(await portListedInProcNetTcp(port)).toBe(true);
  const report = await attackAsNobody(
    port,
    `127.0.0.1:${String(port)}`,
    "127.0.0.1",
  );
  const marker = await markerText(started.marker);
  expect(report.attackerUid).toBe(NOBODY_UID);
  expect(report.attackerUid).not.toBe(process.getuid?.());
  expect({
    sessionHeaderIssued: report.sessionHeaderIssued,
    steps: report.steps.map(({ name, status }) => ({ name, status })),
    sessionOpened: started.lines.some((line) =>
      line.includes("MCP HTTP session opened"),
    ),
    routeInvoked: started.routeHits.count > 0,
    gdbSpawnedAsListener: marker.includes(
      `uid=${String(process.getuid?.() ?? "")}`,
    ),
    shellCommandExecuted: marker.includes(SHELL_PROBE),
  }).toEqual({
    sessionHeaderIssued: false,
    steps: [
      { name: "initialize", status: 401 },
      { name: "tools/list", status: 401 },
      { name: "start_gdb_session", status: 401 },
      { name: "gdb_console", status: 401 },
      { name: "GET /mcp", status: 401 },
      { name: "DELETE /mcp", status: 401 },
      { name: "POST /agentenv", status: 401 },
    ],
    sessionOpened: false,
    routeInvoked: false,
    gdbSpawnedAsListener: false,
    shellCommandExecuted: false,
  });
});

it("rejects a missing or non-matching bearer before Host, Origin, and body checks", async () => {
  const started = await startListener();
  const url = new URL(started.served.url);
  const foreignHost = await postJson(url, initializeBody, {
    host: "rea.invalid",
  });
  const foreignOrigin = await postJson(url, initializeBody, {
    origin: "http://attacker.example",
  });
  const missingOrigin = await postJson(url, initializeBody);
  const wrongBearer = await postJson(url, initializeBody, {
    authorization: `Bearer ${"00".repeat(32)}`,
  });
  const basic = await postJson(url, initializeBody, {
    authorization: "Basic bm9ib2R5",
  });
  const batch = await postJson(
    url,
    JSON.stringify([JSON.parse(initializeBody)]),
  );
  const malformed = await postJson(url, "{");
  const listed = await postJson(
    url,
    JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
  );
  const queried = new URL(url);
  queried.searchParams.set("access_token", "00".repeat(32));
  const queryOnly = await postJson(queried, initializeBody);
  const opened = await fetch(new URL("/mcp", url), { method: "GET" });
  const removed = await fetch(new URL("/mcp", url), { method: "DELETE" });
  const route = await fetch(new URL("/agentenv", url), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  expect({
    foreignHost: foreignHost.status,
    foreignOrigin: foreignOrigin.status,
    missingOrigin: missingOrigin.status,
    wrongBearer: wrongBearer.status,
    basic: basic.status,
    batch: batch.status,
    malformed: malformed.status,
    toolsList: listed.status,
    queryOnly: queryOnly.status,
    get: opened.status,
    delete: removed.status,
    route: route.status,
    routeInvoked: started.routeHits.count > 0,
    sessionOpened: started.lines.some((line) =>
      line.includes("MCP HTTP session opened"),
    ),
  }).toEqual({
    foreignHost: 401,
    foreignOrigin: 401,
    missingOrigin: 401,
    wrongBearer: 401,
    basic: 401,
    batch: 401,
    malformed: 401,
    toolsList: 401,
    queryOnly: 401,
    get: 401,
    delete: 401,
    route: 401,
    routeInvoked: false,
    sessionOpened: false,
  });
  for (const response of [foreignHost, missingOrigin, wrongBearer])
    expect(response.headers["mcp-session-id"]).toBeUndefined();
});

it("rejects other accounts on IPv6 loopback and on a non-loopback bind", async () => {
  const loopback = await startListener("::1");
  const loopbackUrl = new URL(loopback.served.url);
  const loopbackReport = await attackAsNobody(
    Number(loopbackUrl.port),
    `[::1]:${loopbackUrl.port}`,
    "::1",
  );
  const wide = await startListener("0.0.0.0");
  const wideUrl = new URL(wide.served.url);
  const wideReport = await attackAsNobody(
    Number(wideUrl.port),
    `127.0.0.1:${wideUrl.port}`,
    "127.0.0.1",
  );
  expect(loopbackReport.attackerUid).toBe(NOBODY_UID);
  expect(wideReport.attackerUid).toBe(NOBODY_UID);
  expect(
    loopbackReport.steps.find((step) => step.name === "initialize")?.status,
  ).toBe(401);
  expect(
    wideReport.steps.find((step) => step.name === "initialize")?.status,
  ).toBe(401);
  expect(await markerText(loopback.marker)).toBe("");
  expect(await markerText(wide.marker)).toBe("");
});

const connectOperator = async (
  url: string,
  credential: string,
): Promise<{ client: Client; sessionId: string | undefined }> => {
  const transport = new StreamableHTTPClientTransport(new URL(url), {
    authProvider: { token: async () => credential },
  });
  const client = new Client({ name: "operator", version: "1" });
  await client.connect(transport);
  return { client, sessionId: transport.sessionId };
};

it("binds session replacement and GDB console execution to the announced bearer", async () => {
  const started = await startListener();
  const url = new URL(started.served.url);
  const probe = await postJson(url, initializeBody);
  const credential = await operatorCredential(started.lines);
  expect({
    announced: credential !== undefined,
    unauthenticatedInitialize: probe.status,
  }).toEqual({ announced: true, unauthenticatedInitialize: 401 });
  if (credential === undefined) return;
  expect(CREDENTIAL_TEXT.test(credential)).toBe(true);
  const foreign = await postJson(url, initializeBody, {
    authorization: `Bearer ${credential}`,
    host: "rea.invalid",
  });
  expect(foreign.status).toBe(403);
  const admitted = await postJson(url, initializeBody, {
    authorization: `Bearer ${credential}`,
  });
  expect(admitted.status).toBe(200);

  const operator = await connectOperator(started.served.url, credential);
  const echoed = await operator.client.callTool({
    name: "echo",
    arguments: { text: "operator" },
  });
  expect(echoed.content).toEqual([{ type: "text", text: "operator" }]);
  expect(started.toolHits.count).toBe(1);

  const replacementsBefore = started.lines.filter((line) =>
    line.includes("MCP HTTP session replaced"),
  ).length;
  const takeover = await attackAsNobody(
    Number(url.port),
    `127.0.0.1:${url.port}`,
    "127.0.0.1",
  );
  expect(takeover.steps.every((step) => step.status === 401)).toBe(true);
  expect(
    started.lines.filter((line) => line.includes("MCP HTTP session replaced"))
      .length,
  ).toBe(replacementsBefore);
  expect(await markerText(started.marker)).toBe("");
  const stillThere = await operator.client.callTool({
    name: "echo",
    arguments: { text: "still" },
  });
  expect(stillThere.content).toEqual([{ type: "text", text: "still" }]);

  const stolen = await postJson(
    url,
    toolCallBody(9, "echo", { text: "stolen" }),
    operator.sessionId === undefined
      ? {}
      : { "mcp-session-id": operator.sessionId },
  );
  expect(stolen.status).toBe(401);
  expect(started.toolHits.count).toBe(2);

  const mismatched = await postJson(
    url,
    toolCallBody(10, "echo", { text: "other-session" }),
    {
      authorization: `Bearer ${credential}`,
      "mcp-session-id": "00000000-0000-4000-8000-000000000099",
    },
  );
  expect(mismatched.status).toBe(404);
  expect(started.toolHits.count).toBe(2);

  const prefix = credential.slice(0, -1);
  const embedded = `x${credential}`;
  const flipped = `${credential.slice(0, -1)}${credential.endsWith("0") ? "1" : "0"}`;
  for (const authorization of [
    `Bearer ${prefix}`,
    `Bearer ${embedded}`,
    `Bearer ${flipped}`,
    credential,
  ]) {
    const rejected = await postJson(url, initializeBody, { authorization });
    expect(rejected.status).toBe(401);
  }
  const queried = new URL(url);
  queried.searchParams.set("access_token", credential);
  expect((await postJson(queried, initializeBody)).status).toBe(401);

  const startedDebugger = await operator.client.callTool({
    name: "start_gdb_session",
    arguments: {},
  });
  const gdbSession = z
    .object({ session_id: z.string().uuid() })
    .parse(startedDebugger.structuredContent).session_id;
  const beforeConsole = await markerText(started.marker);
  expect(beforeConsole).toContain(`uid=${String(process.getuid?.() ?? "")}`);
  expect(beforeConsole).not.toContain(SHELL_PROBE);
  const stolenConsole = await postJson(
    url,
    toolCallBody(11, "gdb_console", {
      session_id: gdbSession,
      command: `shell printf ${SHELL_PROBE}`,
      detail: "complete",
    }),
    { "mcp-session-id": operator.sessionId ?? "" },
  );
  expect(stolenConsole.status).toBe(401);
  expect(await markerText(started.marker)).not.toContain(SHELL_PROBE);
  const wrongGdbSession = await operator.client.callTool({
    name: "gdb_console",
    arguments: {
      session_id: "00000000-0000-4000-8000-000000000099",
      command: `shell printf ${SHELL_PROBE}`,
      detail: "complete",
    },
  });
  expect(wrongGdbSession.isError).toBe(true);
  expect(await markerText(started.marker)).not.toContain(SHELL_PROBE);
  const consoleResult = await operator.client.callTool({
    name: "gdb_console",
    arguments: {
      session_id: gdbSession,
      command: `shell printf ${SHELL_PROBE}`,
      detail: "complete",
    },
  });
  expect(consoleResult.isError).not.toBe(true);
  expect(await markerText(started.marker)).toContain(SHELL_PROBE);
  await operator.client.close();
});

it("does not let an authenticated request authorize the next request on the connection", async () => {
  const started = await startListener();
  const url = new URL(started.served.url);
  const credential = await operatorCredential(started.lines);
  expect(credential === undefined ? "missing" : "present").toBe("present");
  if (credential === undefined) return;
  const agent = new Agent({ keepAlive: true });
  const send = (
    headers: Record<string, string>,
    body: string,
  ): Promise<number> =>
    new Promise((resolve, reject) => {
      const request = httpRequest(
        url,
        { method: "POST", headers: streamableHeaders(headers), agent },
        (response) => {
          response.resume();
          response.once("end", () => resolve(response.statusCode ?? 0));
          response.once("error", reject);
        },
      );
      request.once("error", reject);
      request.end(body);
    });
  const operator = await connectOperator(started.served.url, credential);
  const opened = await send(
    { authorization: `Bearer ${credential}` },
    toolCallBody(12, "echo", { text: "kept" }),
  );
  // The SDK session is the live one; a header-only call still needs its id.
  expect(opened === 200 || opened === 400).toBe(true);
  const followed = await send(
    operator.sessionId === undefined
      ? {}
      : { "mcp-session-id": operator.sessionId },
    toolCallBody(13, "echo", { text: "trailed" }),
  );
  expect(followed).toBe(401);
  const trailed = started.toolHits.count;
  expect(
    (
      await operator.client.callTool({
        name: "echo",
        arguments: { text: "after" },
      })
    ).content,
  ).toEqual([{ type: "text", text: "after" }]);
  expect(started.toolHits.count).toBe(trailed + 1);
  agent.destroy();
  await operator.client.close();
});

it("compares an equal-length bearer with timingSafeEqual before admission", async () => {
  await mkdir("/workspace/.cache", { recursive: true });
  const directory = await mkdtemp(
    join("/workspace/.cache", "rea-http-auth-compare-"),
  );
  directories.push(directory);
  const wrapper = join(directory, "crypto-observe.mjs");
  const child = join(directory, "compare.mjs");
  const resultPath = join(directory, "result.json");
  await writeFile(
    wrapper,
    `import * as crypto from "node:crypto";
export * from "node:crypto";
const calls = [];
globalThis.__reaTimingSafeEqualCalls = calls;
export function timingSafeEqual(left, right) {
  calls.push([left.byteLength, right.byteLength]);
  return crypto.timingSafeEqual(left, right);
}
`,
  );
  await writeFile(
    child,
    `import { registerHooks } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const workspace = process.env.WORKSPACE;
const { importVerifierSource } = await import(process.env.VERIFIER);
const parent = pathToFileURL(workspace + "/scripts/lib/verifier-source-loader.mjs");
await importVerifierSource(
  pathToFileURL(workspace + "/src/server/http/streamableHttpListenError.ts").href,
  parent,
);
registerHooks({
  resolve(specifier, context, next) {
    const parentUrl = context.parentURL ?? "";
    if (specifier === "node:crypto" && parentUrl.includes("/src/server/"))
      return next(process.env.WRAPPER_URL, context);
    return next(specifier, context);
  },
});
const http = await importVerifierSource(
  pathToFileURL(workspace + "/src/server/http/serveStreamableHttp.ts").href,
  parent,
);
const tracking = await importVerifierSource(
  pathToFileURL(workspace + "/src/server/RequestTrackingMcpServer.ts").href,
  parent,
);
const { z } = await import("zod");
const pino = (await import("pino")).default;
const lines = [];
const served = await http.serveStreamableHttp({
  host: "127.0.0.1",
  port: 0,
  logger: pino({ level: "info" }, { write: (line) => lines.push(line) }),
  createMcpServer: () => {
    const server = new tracking.RequestTrackingMcpServer({ name: "compare", version: "1" });
    server.registerTool(
      "echo",
      { description: "Echo", inputSchema: z.object({ text: z.string() }) },
      ({ text }) => ({ content: [{ type: "text", text }] }),
    );
    return server;
  },
});
const pattern = /^(?:[0-9a-f]{64}|[A-Za-z0-9_-]{43})$/;
let credential;
for (const line of lines) {
  const record = JSON.parse(line);
  if (record.msg !== "MCP transport listening") continue;
  for (const value of Object.values(record)) {
    if (typeof value === "string" && pattern.test(value.trim()))
      credential = value.trim();
    if (typeof value === "string" && value.startsWith("http")) {
      try {
        for (const item of new URL(value).searchParams.values())
          if (pattern.test(item)) credential = item;
      } catch { /* not a credential url */ }
    }
  }
  if (typeof record.client_credential === "string" && pattern.test(record.client_credential.trim()))
    credential = record.client_credential.trim();
  if (typeof record.client_credential_path === "string") {
    const text = readFileSync(record.client_credential_path, "utf8").trim();
    if (pattern.test(text)) credential = text;
  }
}
const body = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "compare", version: "1" },
  },
});
const post = (authorization) => fetch(served.url, {
  method: "POST",
  headers: {
    accept: "application/json, text/event-stream",
    "content-type": "application/json",
    ...(authorization === undefined ? {} : { authorization }),
  },
  body,
});
const open = await post(undefined);
const unauthenticatedStatus = open.status;
await open.body?.cancel();
let wrongStatus = 0;
if (credential !== undefined) {
  const flipped = credential.slice(0, -1) + (credential.endsWith("0") ? "1" : "0");
  if (globalThis.__reaTimingSafeEqualCalls) globalThis.__reaTimingSafeEqualCalls.length = 0;
  const wrong = await post("Bearer " + flipped);
  wrongStatus = wrong.status;
  await wrong.body?.cancel();
}
const calls = globalThis.__reaTimingSafeEqualCalls ?? [];
writeFileSync(process.env.RESULT_PATH, JSON.stringify({
  announced: credential !== undefined,
  unauthenticatedStatus,
  wrongStatus,
  equalLengthComparisons: calls.filter(([left, right]) => left === right && left > 0).length,
}));
await served.close();
`,
  );
  const ran = spawnSync(process.execPath, [child], {
    cwd: "/workspace",
    encoding: "utf8",
    timeout: 20_000,
    env: {
      ...process.env,
      WORKSPACE: "/workspace",
      VERIFIER: "/workspace/scripts/lib/verifier-source-loader.mjs",
      WRAPPER_URL: pathToFileURL(wrapper).href,
      RESULT_PATH: resultPath,
    },
  });
  if (ran.status !== 0)
    throw new Error(`comparison child failed: ${ran.stderr}`);
  const result = JSON.parse(await readFile(resultPath, "utf8")) as {
    announced: boolean;
    unauthenticatedStatus: number;
    wrongStatus: number;
    equalLengthComparisons: number;
  };
  expect({
    announced: result.announced,
    unauthenticatedStatus: result.unauthenticatedStatus,
    wrongStatus: result.wrongStatus,
    equalLengthComparisons: result.equalLengthComparisons > 0,
  }).toEqual({
    announced: true,
    unauthenticatedStatus: 401,
    wrongStatus: 401,
    equalLengthComparisons: true,
  });
});
