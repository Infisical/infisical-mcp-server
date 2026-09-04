const test = require("node:test");
const assert = require("node:assert");
const http = require("node:http");
const path = require("node:path");
const { spawn } = require("node:child_process");

const SERVER = path.join(__dirname, "..", "dist", "index.js");
const TEST_TOKEN = "st.test-only-access-token";
const BACKSTOP_MS = 20000;

// the server reads INFISICAL_* from the environment, so a developer's own
// exported values would otherwise change what these tests exercise
const baseEnv = () => {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith("INFISICAL_")) delete env[key];
  }
  return env;
};

// drives the built server over stdio against a stub API, resolving as soon as
// every expected response id has come back
const run = ({ status = 200, calls = [], listTools = false, env = {} }) =>
  new Promise((resolve, reject) => {
    const api = http.createServer((req, res) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message: "stub" }));
    });
    api.on("error", reject);

    api.listen(0, "127.0.0.1", () => {
      const child = spawn(process.execPath, [SERVER], {
        env: {
          ...baseEnv(),
          INFISICAL_AUTH_METHOD: "access-token",
          INFISICAL_TOKEN: TEST_TOKEN,
          INFISICAL_HOST_URL: `http://127.0.0.1:${api.address().port}`,
          ...env,
        },
        stdio: ["pipe", "pipe", "pipe"],
      });

      const expected = new Set(calls.map((_, i) => 100 + i));
      if (listTools) expected.add(2);

      let stdout = "";
      let stderr = "";
      let settled = false;

      const finish = (extra = {}) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.kill();
        api.close();

        const responses = new Map();
        for (const line of stdout.split("\n")) {
          if (!line.trim()) continue;
          try {
            const message = JSON.parse(line);
            if (message.id !== undefined) responses.set(message.id, message);
          } catch {
            // partial line, ignore
          }
        }
        resolve({ stdout, stderr, responses, ...extra });
      };

      const timer = setTimeout(() => finish({ timedOut: true }), BACKSTOP_MS);

      child.on("error", reject);
      // a startup failure means no responses are coming; do not wait it out
      child.on("exit", () => finish({ exited: true }));

      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
        const seen = new Set();
        for (const line of stdout.split("\n")) {
          if (!line.trim()) continue;
          try {
            const message = JSON.parse(line);
            if (message.id !== undefined) seen.add(message.id);
          } catch {
            // partial line, ignore
          }
        }
        if ([...expected].every((id) => seen.has(id))) finish();
      });

      const send = (message) =>
        child.stdin.write(`${JSON.stringify(message)}\n`);

      send({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "test", version: "0" },
        },
      });
      send({ jsonrpc: "2.0", method: "notifications/initialized" });
      if (listTools) send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
      calls.forEach((params, i) =>
        send({ jsonrpc: "2.0", id: 100 + i, method: "tools/call", params }),
      );
    });
  });

test("a failed list-projects call logs only the formatted message", async () => {
  const { stderr, responses, timedOut } = await run({
    status: 401,
    calls: [{ name: "list-projects", arguments: { type: "secret-manager" } }],
  });

  // guard against a vacuous pass: the request has to have actually failed
  assert.ok(!timedOut, "the server never answered");
  assert.match(stderr, /running on stdio/, "server did not start");
  assert.ok(responses.has(100), "tool call was not answered");
  assert.match(
    stderr,
    /Error retrieving projects/,
    "the error path did not run",
  );

  assert.ok(
    !stderr.includes(TEST_TOKEN),
    "stderr carried request detail beyond the formatted message",
  );
});

test("tools outside the allowlist are neither listed nor callable", async () => {
  const { responses, timedOut } = await run({
    listTools: true,
    calls: [
      {
        name: "delete-secret",
        arguments: {
          projectId: "p",
          environmentSlug: "dev",
          secretName: "s",
        },
      },
    ],
    env: { INFISICAL_ENABLED_TOOLS: "list-projects" },
  });

  assert.ok(!timedOut, "the server never answered");

  const listed = (responses.get(2)?.result?.tools ?? []).map((t) => t.name);
  assert.deepStrictEqual(listed, ["list-projects"], "tools/list was not filtered");

  assert.match(
    responses.get(100)?.error?.message ?? "",
    /is not enabled on this server/,
    "a disabled tool was not refused",
  );
});

test("an unknown tool name is reported as unknown, not as disabled", async () => {
  const { responses, timedOut } = await run({
    calls: [{ name: "get-secrets", arguments: {} }],
  });

  assert.ok(!timedOut, "the server never answered");
  assert.match(
    responses.get(100)?.error?.message ?? "",
    /Unrecognized tool name/,
    "an unknown tool was not reported as unknown",
  );
});
