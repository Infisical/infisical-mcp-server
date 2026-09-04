const test = require("node:test");
const assert = require("node:assert");
const http = require("node:http");
const path = require("node:path");
const { spawn } = require("node:child_process");

const SERVER = path.join(__dirname, "..", "dist", "index.js");
const TEST_TOKEN = "st.test-only-access-token";

// drives the built server over stdio against a stub API
const runToolCall = ({ status, calls, env = {} }) =>
  new Promise((resolve, reject) => {
    const api = http.createServer((req, res) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message: "stub" }));
    });

    api.on("error", reject);

    api.listen(0, "127.0.0.1", () => {
      const child = spawn(process.execPath, [SERVER], {
        env: {
          ...process.env,
          INFISICAL_AUTH_METHOD: "access-token",
          INFISICAL_TOKEN: TEST_TOKEN,
          INFISICAL_HOST_URL: `http://127.0.0.1:${api.address().port}`,
          ...env,
        },
        stdio: ["pipe", "pipe", "pipe"],
      });

      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      child.on("error", reject);

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
      calls.forEach((params, i) =>
        send({ jsonrpc: "2.0", id: 100 + i, method: "tools/call", params }),
      );

      setTimeout(() => {
        child.kill();
        api.close();
        resolve({ stdout, stderr });
      }, 2500);
    });
  });

test("a failed list-projects call logs only the formatted message", async () => {
  const { stdout, stderr } = await runToolCall({
    status: 401,
    calls: [{ name: "list-projects", arguments: { type: "secret-manager" } }],
  });

  // guard against a vacuous pass: the request has to have actually failed
  assert.match(stderr, /running on stdio/, "server did not start");
  assert.match(stdout, /"id":100/, "tool call was not answered");
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

test("a disabled tool is refused without being listed", async () => {
  const { stdout } = await runToolCall({
    status: 200,
    calls: [
      { name: "delete-secret", arguments: {} },
      { name: "list-projects", arguments: { type: "secret-manager" } },
    ],
    env: { INFISICAL_ENABLED_TOOLS: "list-projects" },
  });

  assert.match(stdout, /is not enabled on this server/);
  assert.ok(
    !stdout.includes("Secret deleted successfully"),
    "a disabled tool ran anyway",
  );
});
