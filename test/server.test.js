// These drive the built server over stdio because src/index.ts validates the
// environment at import and exports nothing, leaving no in-process surface.

const test = require("node:test");
const assert = require("node:assert");
const http = require("node:http");
const path = require("node:path");
const { spawn } = require("node:child_process");

const SERVER = path.join(__dirname, "..", "dist", "index.js");
const TEST_TOKEN = "st.test-only-access-token";

const run = ({ status = 200, calls = [], env = {} }) =>
  new Promise((resolve, reject) => {
    const api = http.createServer((_req, res) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end('{"message":"stub"}');
    });
    api.on("error", reject);

    api.listen(0, "127.0.0.1", () => {
      // a developer's own INFISICAL_* values must not change what is exercised
      const inherited = Object.fromEntries(
        Object.entries(process.env).filter(
          ([key]) => !key.startsWith("INFISICAL_"),
        ),
      );

      const child = spawn(process.execPath, [SERVER], {
        env: {
          ...inherited,
          INFISICAL_AUTH_METHOD: "access-token",
          INFISICAL_TOKEN: TEST_TOKEN,
          INFISICAL_HOST_URL: `http://127.0.0.1:${api.address().port}`,
          ...env,
        },
        stdio: ["pipe", "pipe", "pipe"],
      });

      const wanted = new Set([2, ...calls.map((_, i) => 100 + i)]);

      const responses = new Map();
      let stderr = "";
      let buffer = "";
      let settled = false;

      const finish = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        child.kill();
        api.close();
        resolve({
          responses,
          stderr,
          missing: [...wanted].filter((id) => !responses.has(id)),
        });
      };

      const timer = setTimeout(finish, 20000);
      child.on("error", reject);
      child.on("exit", finish);
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });

      child.stdout.on("data", (chunk) => {
        buffer += chunk;
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines.filter((l) => l.trim())) {
          const message = JSON.parse(line);
          if (message.id !== undefined) responses.set(message.id, message);
        }
        if ([...wanted].every((id) => responses.has(id))) finish();
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
      send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
      calls.forEach((params, i) =>
        send({ jsonrpc: "2.0", id: 100 + i, method: "tools/call", params }),
      );
    });
  });

test("a failed list-projects call logs only the formatted message", async () => {
  const { stderr, missing } = await run({
    status: 401,
    calls: [{ name: "list-projects", arguments: { type: "secret-manager" } }],
  });

  assert.deepStrictEqual(missing, [], "the server did not answer");
  assert.match(
    stderr,
    /Error retrieving projects/,
    "the error path did not run",
  );
  assert.ok(
    !stderr.includes(TEST_TOKEN),
    "stderr carried more than the formatted message",
  );
});

test("tools/list is filtered, and refused calls say why", async () => {
  const { responses, missing } = await run({
    calls: [
      {
        name: "delete-secret",
        arguments: { projectId: "p", environmentSlug: "dev", secretName: "s" },
      },
      { name: "get-secrets", arguments: {} },
    ],
    env: { INFISICAL_ENABLED_TOOLS: "list-projects" },
  });

  assert.deepStrictEqual(missing, [], "the server did not answer");
  assert.deepStrictEqual(
    responses.get(2).result.tools.map((tool) => tool.name),
    ["list-projects"],
    "tools/list was not filtered",
  );
  assert.match(
    responses.get(100).error.message,
    /is not enabled on this server/,
    "a disabled tool was not refused",
  );
  assert.match(
    responses.get(101).error.message,
    /Unrecognized tool name/,
    "an unknown tool was reported as disabled",
  );
});
