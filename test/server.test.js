// Each test connects an MCP client to a server built from dist/index.js over
// an in-memory transport, with a fake Infisical API on localhost behind it.
// The real HTTP client runs, so the requests asserted here are the ones
// Infisical would receive. `npm test` builds first.

const { describe, test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const path = require("node:path");
const readline = require("node:readline");
const { spawn } = require("node:child_process");
const { Client } = require("@modelcontextprotocol/sdk/client/index.js");
const { InMemoryTransport } = require("@modelcontextprotocol/sdk/inMemory.js");
const { ErrorCode } = require("@modelcontextprotocol/sdk/types.js");
const {
  createServer,
  getEnvironmentVariables,
  getStartupLogEntry,
} = require("../dist/index.js");

const SECRET_VALUE = "s3cr3t-value";
const CLIENT_SECRET = "universal-auth-client-secret";
const MASKED_VALUE = "<masked>";
const READ_ONLY_TOOLS = ["list-secrets", "get-secret", "list-projects"];
const LOGIN_PATH = "/api/v1/auth/universal-auth/login";
const RENEW_PATH = "/api/v1/auth/token/renew";

// shaped like Infisical's tokens; the server treats it as opaque, and takes
// the lifetime from the login's expiresIn
const accessToken = (ttlSeconds) => {
  const iat = Math.floor(Date.now() / 1000);
  return [
    Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url"),
    Buffer.from(JSON.stringify({ iat, exp: iat + ttlSeconds })).toString("base64url"),
    "signature",
  ].join(".");
};

const fakeSecret = (secretKey, query) => {
  const hidden = query.viewSecretValue === "false";
  return {
    secretKey,
    secretValue: hidden ? "<hidden-by-infisical>" : SECRET_VALUE,
    secretValueHidden: hidden,
  };
};

const defaultResponse = ({ method, path, query, body }) => {
  if (method === "POST" && path === LOGIN_PATH) {
    return [200, { accessToken: accessToken(3600), expiresIn: 3600 }];
  }

  // renewing keeps the token and extends its lifetime
  if (method === "POST" && path === RENEW_PATH) {
    return [200, { accessToken: body.accessToken, expiresIn: 3600, accessTokenMaxTTL: 2592000 }];
  }

  if (method === "GET" && path === "/api/v4/secrets") {
    return [
      200,
      {
        secrets: [fakeSecret("DB_PASSWORD", query)],
        ...(query.includeImports === "true" && {
          imports: [
            {
              secretPath: "/shared",
              environment: "dev",
              secrets: [fakeSecret("SHARED_KEY", query)],
            },
          ],
        }),
      },
    ];
  }

  const secretRoute = path.match(/^\/api\/v4\/secrets\/(.+)$/);
  if (secretRoute) {
    const secretKey = decodeURIComponent(secretRoute[1]);
    switch (method) {
      case "GET":
        return [200, { secret: fakeSecret(secretKey, query) }];
      case "POST":
        return [200, { secret: { secretKey, secretValue: body.secretValue } }];
      case "PATCH":
        return [
          200,
          {
            secret: {
              secretKey: body.newSecretName ?? secretKey,
              secretValue: body.secretValue ?? SECRET_VALUE,
            },
          },
        ];
      case "DELETE":
        return [200, { secret: { secretKey } }];
    }
  }

  if (method === "GET" && path === "/api/v1/workspace") {
    return [
      200,
      {
        workspaces: [
          {
            id: "project-1",
            name: "Payments",
            slug: "payments",
            orgId: "org-1",
            type: "secret-manager",
            hasDeleteProtection: false,
            environments: [{ id: "env-1", name: "Development", slug: "dev" }],
          },
        ],
      },
    ];
  }

  if (method === "POST" && path === "/api/v2/workspace") {
    return [200, { project: { id: "project-2", name: body.projectName } }];
  }

  if (method === "POST" && /^\/api\/v1\/workspace\/[^/]+\/environments$/.test(path)) {
    return [200, { environment: { id: "env-2", name: body.name, slug: body.slug } }];
  }

  if (method === "POST" && path === "/api/v1/folders") {
    return [200, { folder: { id: "folder-1", name: body.name } }];
  }

  if (method === "POST" && /^\/api\/v2\/workspace\/[^/]+\/memberships$/.test(path)) {
    return [200, { memberships: [{ id: "membership-1" }] }];
  }

  return [404, { message: `No fake route for ${method} ${path}` }];
};

// returned by `respond` to leave a request unanswered
const HANG = Symbol("hang");

// `respond` can answer a request itself, or return undefined to fall through
const startApi = async (respond) => {
  const requests = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      const url = new URL(req.url, "http://localhost");
      const request = {
        method: req.method,
        path: url.pathname,
        query: Object.fromEntries(url.searchParams),
        body: raw ? JSON.parse(raw) : undefined,
        authorization: req.headers.authorization,
        userAgent: req.headers["user-agent"],
      };
      requests.push(request);

      // a string payload is sent as an HTML page, as a web server's 404 is
      const send = (status, payload) => {
        const isHtml = typeof payload === "string";
        res.writeHead(status, { "content-type": isHtml ? "text/html" : "application/json" });
        res.end(isHtml ? payload : JSON.stringify(payload));
      };

      const response = respond?.(request) ?? defaultResponse(request);
      if (response === HANG) {
        // a test can still answer it later, unless the client hangs up first
        request.respond = send;
        res.on("close", () => (request.closed = !res.writableEnded));
        return;
      }

      send(...response);
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));

  return {
    url: `http://127.0.0.1:${server.address().port}`,
    requests,
    close: () => {
      server.closeAllConnections();
      return new Promise((resolve) => server.close(resolve));
    },
  };
};

const waitFor = async (condition) => {
  const deadline = Date.now() + 2000;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("Timed out waiting");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
};

const setup = async (t, { env = {}, respond, options = {} } = {}) => {
  const api = await startApi(respond);
  t.after(() => api.close());

  const logs = [];
  const server = createServer(
    getEnvironmentVariables({
      INFISICAL_HOST_URL: api.url,
      INFISICAL_UNIVERSAL_AUTH_CLIENT_ID: "universal-auth-client-id",
      INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET: CLIENT_SECRET,
      ...env,
    }),
    { log: (entry) => logs.push(entry), ...options },
  );

  const client = new Client({ name: "test-client", version: "1.0.0" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);
  t.after(() => client.close());

  const call = async (name, args) => {
    const result = await client.callTool({ name, arguments: args });
    assert.ok(!result.isError, `${name} failed: ${result.content[0].text}`);
    return result.content[0].text;
  };

  // a tool that fails while running returns a result with isError set
  const callError = async (name, args) => {
    const result = await client.callTool({ name, arguments: args });
    assert.equal(result.isError, true, `${name} was expected to fail`);
    return result.content[0].text;
  };

  // requests past the login, which every first call makes, and renewals
  const secretRequests = () =>
    api.requests.filter((request) => !request.path.includes("/auth/"));
  const logins = () => api.requests.filter((request) => request.path === LOGIN_PATH);
  const renewals = () => api.requests.filter((request) => request.path === RENEW_PATH);

  return { client, api, logs, call, callError, secretRequests, logins, renewals };
};

// the JSON a tool response carries after its leading sentence
const parseResponse = (text) => JSON.parse(text.slice(text.indexOf("{")));

const ALL_TOOLS = { INFISICAL_ENABLED_TOOLS: "all" };
const READ_ONLY = { INFISICAL_ENABLED_TOOLS: READ_ONLY_TOOLS.join(",") };
const MASKED = { INFISICAL_MASK_SECRET_VALUES: "true" };
const SECRET_LOCATION = { projectId: "project-1", environmentSlug: "dev" };

describe("configuration", () => {
  const parse = (env) =>
    getEnvironmentVariables({
      INFISICAL_AUTH_METHOD: "access-token",
      INFISICAL_TOKEN: "token",
      ...env,
    });

  // the hardening controls are opt-in, so an existing setup keeps working
  test("defaults to every tool, unmasked values and an audit log", () => {
    const env = parse({});
    assert.equal(env.INFISICAL_ENABLED_TOOLS.length, 10);
    assert.equal(env.INFISICAL_MASK_SECRET_VALUES, false);
    assert.equal(env.INFISICAL_AUDIT_LOG, true);
  });

  test("treats a blank masking value as unset", () => {
    assert.equal(parse({ INFISICAL_MASK_SECRET_VALUES: " " }).INFISICAL_MASK_SECRET_VALUES, false);
    assert.equal(parse({ INFISICAL_MASK_SECRET_VALUES: "TRUE" }).INFISICAL_MASK_SECRET_VALUES, true);
  });

  test("takes the host with or without a trailing slash or /api", () => {
    for (const [hostUrl, expected] of [
      ["https://eu.infisical.com", "https://eu.infisical.com"],
      ["https://eu.infisical.com/", "https://eu.infisical.com"],
      ["https://infisical.example.com/api", "https://infisical.example.com"],
      ["https://infisical.example.com/api/", "https://infisical.example.com"],
      ["https://example.com/infisical/api/", "https://example.com/infisical"],
      // a host that is itself called api, as an internal service name can be
      ["http://api/", "http://api"],
    ]) {
      assert.equal(parse({ INFISICAL_HOST_URL: hostUrl }).INFISICAL_HOST_URL, expected, hostUrl);
    }
  });

  test("exposes every tool for all", () => {
    assert.equal(parse(ALL_TOOLS).INFISICAL_ENABLED_TOOLS.length, 10);
  });

  test("gives each parse its own tool list", () => {
    parse({}).INFISICAL_ENABLED_TOOLS.length = 0;
    parse(ALL_TOOLS).INFISICAL_ENABLED_TOOLS.length = 0;

    assert.equal(parse({}).INFISICAL_ENABLED_TOOLS.length, 10);
    assert.equal(parse(ALL_TOOLS).INFISICAL_ENABLED_TOOLS.length, 10);
  });

  for (const [description, env, message] of [
    ["an unknown tool", { INFISICAL_ENABLED_TOOLS: "get-secret,read-minds" }, /unknown tool\(s\): read-minds/],
    ["an empty tool list", { INFISICAL_ENABLED_TOOLS: " , " }, /lists no tools/],
    ["all mixed with names", { INFISICAL_ENABLED_TOOLS: "all,get-secret" }, /not both/],
    ["a masking value that is not a boolean", { INFISICAL_MASK_SECRET_VALUES: "yes" }, /must be "true" or "false"/],
    ["token auth without a token", { INFISICAL_TOKEN: undefined }, /INFISICAL_TOKEN is not set/],
    ["universal auth without a client secret", { INFISICAL_AUTH_METHOD: "universal-auth", INFISICAL_UNIVERSAL_AUTH_CLIENT_ID: "id" }, /CLIENT_SECRET is not set/],
  ]) {
    test(`refuses to start with ${description}`, () => {
      assert.throws(
        () => parse(env),
        (err) => err.issues.some((issue) => message.test(issue.message)),
      );
    });
  }
});

describe("tool gating", () => {
  test("lists only the enabled tools", async (t) => {
    const { client } = await setup(t, {
      env: { INFISICAL_ENABLED_TOOLS: "get-secret,delete-secret" },
    });

    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((tool) => tool.name).sort(), ["delete-secret", "get-secret"]);
    const deleteSecret = tools.find((tool) => tool.name === "delete-secret");
    assert.equal(deleteSecret.annotations.destructiveHint, true);
  });

  test("lists every tool by default", async (t) => {
    const { client } = await setup(t);

    const { tools } = await client.listTools();
    assert.equal(tools.length, 10);
  });

  test("lists only tools that read under the read-only allowlist", async (t) => {
    const { client } = await setup(t, { env: READ_ONLY });

    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((tool) => tool.name).sort(), [...READ_ONLY_TOOLS].sort());
    assert.ok(tools.every((tool) => tool.annotations.readOnlyHint));
  });

  // both are protocol errors rather than failed results, as the MCP spec asks
  test("refuses a disabled tool before authenticating", async (t) => {
    const { call, api, logs } = await setup(t, { env: READ_ONLY });

    await assert.rejects(
      call("delete-secret", { ...SECRET_LOCATION, secretName: "DB_PASSWORD" }),
      (err) => {
        assert.equal(err.code, ErrorCode.InvalidParams);
        assert.match(err.message, /not enabled on this server\. Enabled tools: list-secrets, get-secret, list-projects/);
        // the model reads this, and one that can edit files could follow a
        // hint to change the server's configuration and enable the tool
        assert.ok(!err.message.includes("INFISICAL_ENABLED_TOOLS"));
        return true;
      },
    );
    assert.equal(api.requests.length, 0);
    assert.equal(logs[0].outcome, "denied");
  });

  test("refuses an unknown tool", async (t) => {
    const { call, api } = await setup(t, { env: ALL_TOOLS });

    await assert.rejects(call("read-minds", {}), (err) => {
      assert.equal(err.code, ErrorCode.InvalidParams);
      assert.match(err.message, /Unrecognized tool name: read-minds/);
      return true;
    });
    assert.equal(api.requests.length, 0);
  });
});

describe("reading secrets", () => {
  test("list-secrets masks values and asks Infisical not to send them", async (t) => {
    const { call, secretRequests } = await setup(t, { env: MASKED });

    const text = await call("list-secrets", SECRET_LOCATION);

    const [request] = secretRequests();
    assert.equal(request.query.viewSecretValue, "false");
    assert.equal(request.query.projectId, "project-1");
    assert.equal(request.query.environment, "dev");
    assert.equal(request.query.secretPath, "/");

    const response = JSON.parse(text);
    assert.deepEqual(response.secrets, [{ secretKey: "DB_PASSWORD", secretValue: MASKED_VALUE }]);
    assert.deepEqual(response.imports[0].secrets, [{ secretKey: "SHARED_KEY", secretValue: MASKED_VALUE }]);
    assert.ok(!text.includes("hidden-by-infisical"));
  });

  test("list-secrets returns imports, using the parameter name the API reads", async (t) => {
    const { call, secretRequests } = await setup(t);

    const response = JSON.parse(await call("list-secrets", SECRET_LOCATION));

    assert.equal(secretRequests()[0].query.includeImports, "true");
    assert.equal(response.imports[0].secretPath, "/shared");
  });

  test("list-secrets returns imports from v4 releases that read include_imports", async (t) => {
    // v4 read the flag as include_imports until v0.158.3
    const { call } = await setup(t, {
      respond: (request) =>
        request.path === "/api/v4/secrets"
          ? defaultResponse({
              ...request,
              query: { ...request.query, includeImports: request.query.include_imports },
            })
          : undefined,
    });

    const response = JSON.parse(await call("list-secrets", SECRET_LOCATION));

    assert.equal(response.imports[0].secretPath, "/shared");
  });

  test("list-secrets returns values by default", async (t) => {
    const { call, secretRequests } = await setup(t);

    const response = JSON.parse(await call("list-secrets", SECRET_LOCATION));

    assert.equal(secretRequests()[0].query.viewSecretValue, "true");
    assert.equal(response.secrets[0].secretValue, SECRET_VALUE);
    assert.equal(response.imports[0].secrets[0].secretValue, SECRET_VALUE);
  });

  test("get-secret masks the value and passes its options through", async (t) => {
    const { call, secretRequests } = await setup(t, { env: MASKED });

    const text = await call("get-secret", {
      ...SECRET_LOCATION,
      secretName: "API KEY",
      secretPath: "/backend",
      includeImports: false,
      expandSecretReferences: false,
    });

    const [request] = secretRequests();
    assert.equal(request.path, "/api/v4/secrets/API%20KEY");
    assert.equal(request.query.includeImports, "false");
    assert.equal(request.query.expandSecretReferences, "false");
    assert.equal(request.query.secretPath, "/backend");
    assert.equal(request.query.viewSecretValue, "false");
    assert.equal(parseResponse(text).secretValue, MASKED_VALUE);
  });

  test("get-secret returns the value by default", async (t) => {
    const { call } = await setup(t);

    const text = await call("get-secret", { ...SECRET_LOCATION, secretName: "DB_PASSWORD" });

    assert.equal(parseResponse(text).secretValue, SECRET_VALUE);
  });
});

describe("writing secrets", () => {
  test("create-secret stores the value and masks it in the response", async (t) => {
    const { call, secretRequests } = await setup(t, { env: { ...ALL_TOOLS, ...MASKED } });

    const text = await call("create-secret", {
      ...SECRET_LOCATION,
      secretName: "NEW_KEY",
      secretValue: SECRET_VALUE,
    });

    const [request] = secretRequests();
    assert.equal(request.method, "POST");
    assert.equal(request.path, "/api/v4/secrets/NEW_KEY");
    assert.equal(request.body.secretValue, SECRET_VALUE);
    assert.equal(request.body.projectId, "project-1");
    assert.equal(request.body.environment, "dev");
    assert.equal(request.body.secretPath, "/");
    assert.equal(parseResponse(text).secretValue, MASKED_VALUE);
    assert.ok(!text.includes(SECRET_VALUE));
  });

  test("update-secret renames a secret without touching its value", async (t) => {
    const { call, secretRequests } = await setup(t, { env: ALL_TOOLS });

    await call("update-secret", {
      ...SECRET_LOCATION,
      secretName: "OLD_NAME",
      newSecretName: "NEW_NAME",
    });

    const [request] = secretRequests();
    assert.equal(request.method, "PATCH");
    assert.equal(request.path, "/api/v4/secrets/OLD_NAME");
    assert.equal(request.body.projectId, "project-1");
    assert.equal(request.body.environment, "dev");
    assert.equal(request.body.newSecretName, "NEW_NAME");
    assert.ok(!("secretValue" in request.body));
  });

  test("update-secret sends a new value and masks it in the response", async (t) => {
    const { call, secretRequests } = await setup(t, { env: { ...ALL_TOOLS, ...MASKED } });

    const text = await call("update-secret", {
      ...SECRET_LOCATION,
      secretName: "DB_PASSWORD",
      secretValue: "rotated-value",
    });

    assert.equal(secretRequests()[0].body.secretValue, "rotated-value");
    assert.equal(parseResponse(text).secretValue, MASKED_VALUE);
  });

  test("delete-secret deletes the named secret", async (t) => {
    const { call, secretRequests } = await setup(t, { env: ALL_TOOLS });

    const text = await call("delete-secret", {
      ...SECRET_LOCATION,
      secretName: "DB_PASSWORD",
      secretPath: "/backend",
    });

    const [request] = secretRequests();
    assert.equal(request.method, "DELETE");
    assert.equal(request.path, "/api/v4/secrets/DB_PASSWORD");
    assert.equal(request.body.projectId, "project-1");
    assert.equal(request.body.environment, "dev");
    assert.equal(request.body.secretPath, "/backend");
    assert.equal(text, "Secret deleted successfully: DB_PASSWORD");
  });
});

describe("writes that need approval", () => {
  const CHANGE_REQUEST = {
    id: "3f2c1a9e-0000-4000-8000-000000000001",
    slug: "quiet-otter",
    status: "open",
    policyId: "3f2c1a9e-0000-4000-8000-000000000002",
  };

  for (const [tool, method, args] of [
    ["create-secret", "POST", { secretName: "NEW_KEY", secretValue: SECRET_VALUE }],
    ["update-secret", "PATCH", { secretName: "DB_PASSWORD", secretValue: "rotated-value" }],
    ["delete-secret", "DELETE", { secretName: "DB_PASSWORD" }],
  ]) {
    test(`${tool} reports a pending change request instead of a change`, async (t) => {
      const { call, logs } = await setup(t, {
        env: ALL_TOOLS,
        respond: (request) =>
          request.method === method && request.path.startsWith("/api/v4/secrets/")
            ? [200, { approval: CHANGE_REQUEST }]
            : undefined,
      });

      const text = await call(tool, { ...SECRET_LOCATION, ...args });

      assert.match(text, /not applied yet/);
      assert.equal(logs[0].outcome, "pending_approval");
      assert.deepEqual(parseResponse(text), {
        id: CHANGE_REQUEST.id,
        slug: CHANGE_REQUEST.slug,
        status: "open",
      });
      assert.ok(!text.includes(SECRET_VALUE));
    });
  }
});

describe("Infisical before v0.150.0, without the v4 secrets API", () => {
  // no v4 routes, and v3 routes that only read the project and imports flag
  // under their v3 names
  const withoutV4 = (request) => {
    if (request.path.startsWith("/api/v4/")) {
      return [404, { message: `Route ${request.method}:${request.path} not found`, error: "Not Found" }];
    }
    if (!request.path.startsWith("/api/v3/secrets/raw")) return undefined;

    const { workspaceId, include_imports, ...query } = request.query;
    const { workspaceId: bodyWorkspaceId, ...body } = request.body ?? {};
    if (!workspaceId && !bodyWorkspaceId) return [400, { message: "Missing project id" }];

    return defaultResponse({
      ...request,
      path: request.path.replace("/api/v3/secrets/raw", "/api/v4/secrets"),
      query: { ...query, includeImports: include_imports },
      body,
    });
  };

  test("falls back to the v3 routes, and stays on them", async (t) => {
    const { call, logs, secretRequests } = await setup(t, { env: ALL_TOOLS, respond: withoutV4 });

    const listed = JSON.parse(await call("list-secrets", SECRET_LOCATION));
    await call("create-secret", { ...SECRET_LOCATION, secretName: "NEW_KEY", secretValue: SECRET_VALUE });

    assert.equal(listed.imports[0].secretPath, "/shared");
    assert.deepEqual(
      secretRequests().map((request) => `${request.method} ${request.path}`),
      ["GET /api/v4/secrets", "GET /api/v3/secrets/raw", "POST /api/v3/secrets/raw/NEW_KEY"],
    );
    const [, list, create] = secretRequests();
    assert.equal(list.query.workspaceId, "project-1");
    assert.equal(list.query.include_imports, "true");
    assert.equal(create.body.workspaceId, "project-1");
    assert.ok(!("projectId" in create.body));
    assert.equal(logs.filter((entry) => entry.event === "secrets_api_fallback").length, 1);
  });

  test("falls back when the v4 route gets a web server's HTML 404", async (t) => {
    // standalone images up to v0.100.0 hand unknown paths to the frontend
    const { call, secretRequests } = await setup(t, {
      respond: (request) =>
        request.path.startsWith("/api/v4/")
          ? [404, "<!DOCTYPE html><title>404: This page could not be found</title>"]
          : withoutV4(request),
    });

    const listed = JSON.parse(await call("list-secrets", SECRET_LOCATION));

    assert.equal(listed.secrets[0].secretKey, "DB_PASSWORD");
    assert.equal(secretRequests()[1].path, "/api/v3/secrets/raw");
  });

  test("goes back to v4 after a 404 page that may have come from a proxy", async (t) => {
    // a 404 page with no API message is what old standalone images send, but
    // a proxy in front of a current Infisical can send one too
    let pageSent = false;
    const { call, logs, secretRequests } = await setup(t, {
      respond: (request) => {
        if (request.path.startsWith("/api/v4/") && !pageSent) {
          pageSent = true;
          return [404, "<!DOCTYPE html><title>404 Not Found</title>"];
        }
        return request.path.startsWith("/api/v3/") ? withoutV4(request) : undefined;
      },
    });

    await call("list-secrets", SECRET_LOCATION);
    await call("list-secrets", SECRET_LOCATION);

    assert.deepEqual(
      secretRequests().map((request) => request.path),
      ["/api/v4/secrets", "/api/v3/secrets/raw", "/api/v4/secrets"],
    );
    const [fallback] = logs.filter((entry) => entry.event === "secrets_api_fallback");
    assert.match(fallback.message, /proxy/);
  });

  test("logs the switch once when calls arrive together", async (t) => {
    const { call, logs } = await setup(t, { respond: withoutV4 });

    await Promise.all(
      Array.from({ length: 5 }, () => call("list-secrets", SECRET_LOCATION)),
    );

    assert.equal(logs.filter((entry) => entry.event === "secrets_api_fallback").length, 1);
  });

  test("does not fall back when v4 reports a secret that does not exist", async (t) => {
    const { callError, secretRequests } = await setup(t, {
      respond: ({ path }) =>
        path.startsWith("/api/v4/secrets/")
          ? [404, { message: "Secret with name 'MISSING' not found" }]
          : undefined,
    });

    assert.match(
      await callError("get-secret", { ...SECRET_LOCATION, secretName: "MISSING" }),
      /404: Secret with name 'MISSING' not found/,
    );
    assert.equal(secretRequests().length, 1);
  });
});

describe("projects, environments, folders and members", () => {
  test("list-projects filters by type, and omits the filter for all", async (t) => {
    const { call, secretRequests } = await setup(t);

    const text = await call("list-projects", { type: "kms" });
    await call("list-projects", {});

    const [filtered, unfiltered] = secretRequests();
    assert.equal(filtered.query.type, "kms");
    assert.ok(!("type" in unfiltered.query));
    const projects = JSON.parse(text.slice(text.indexOf("[")));
    assert.equal(projects[0].slug, "payments");
    assert.equal(projects[0].environments[0].slug, "dev");
  });

  test("create-project sends the project details", async (t) => {
    const { call, secretRequests } = await setup(t, { env: ALL_TOOLS });

    await call("create-project", { projectName: "Billing", type: "secret-manager", slug: "billing" });

    const [request] = secretRequests();
    assert.equal(request.path, "/api/v2/workspace");
    assert.equal(request.body.projectName, "Billing");
    assert.equal(request.body.type, "secret-manager");
    assert.equal(request.body.slug, "billing");
  });

  test("create-project rejects a type the API does not have", async (t) => {
    const { callError, secretRequests } = await setup(t, { env: ALL_TOOLS });

    assert.match(
      await callError("create-project", { projectName: "Billing", type: "everything" }),
      /Invalid arguments: type/,
    );
    assert.equal(secretRequests().length, 0);
  });

  test("create-environment creates it in the given project", async (t) => {
    const { call, secretRequests } = await setup(t, { env: ALL_TOOLS });

    await call("create-environment", { projectId: "project-1", name: "Staging", slug: "staging" });

    const [request] = secretRequests();
    assert.equal(request.path, "/api/v1/workspace/project-1/environments");
    assert.equal(request.body.slug, "staging");
  });

  test("create-folder creates it at the given path", async (t) => {
    const { call, secretRequests } = await setup(t, { env: ALL_TOOLS });

    await call("create-folder", { projectId: "project-1", environment: "dev", name: "backend", path: "/apps" });

    const [request] = secretRequests();
    assert.equal(request.path, "/api/v1/folders");
    assert.equal(request.body.workspaceId, "project-1");
    assert.equal(request.body.path, "/apps");
    assert.equal(request.body.name, "backend");
  });

  test("invite-members-to-project invites with the given roles", async (t) => {
    const { call, secretRequests } = await setup(t, { env: ALL_TOOLS });

    await call("invite-members-to-project", {
      projectId: "project-1",
      emails: ["dev@example.com"],
      roleSlugs: ["viewer"],
    });

    const [request] = secretRequests();
    assert.equal(request.path, "/api/v2/workspace/project-1/memberships");
    assert.deepEqual(request.body.emails, ["dev@example.com"]);
    assert.deepEqual(request.body.roleSlugs, ["viewer"]);
  });

  test("invite-members-to-project needs an email or a username", async (t) => {
    const { callError, secretRequests } = await setup(t, { env: ALL_TOOLS });

    assert.match(
      await callError("invite-members-to-project", { projectId: "project-1", emails: [] }),
      /Either usernames or emails must be provided/,
    );
    assert.equal(secretRequests().length, 0);
  });

  test("invite-members-to-project refuses more than 100 entries without checking each one", async (t) => {
    const { callError, secretRequests } = await setup(t, { env: ALL_TOOLS });

    for (const field of ["emails", "usernames", "roleSlugs"]) {
      assert.equal(
        await callError("invite-members-to-project", {
          projectId: "project-1",
          usernames: ["dev"],
          [field]: Array(101).fill(0),
        }),
        `Invalid arguments: ${field}: Too big: expected array to have <=100 items`,
      );
    }
    assert.equal(secretRequests().length, 0);
  });

  test("rejects project IDs that no URL can address", async (t) => {
    const { callError, secretRequests } = await setup(t, { env: ALL_TOOLS });

    for (const projectId of ["", " ", ".", ".."]) {
      assert.match(
        await callError("create-environment", { projectId, name: "Staging", slug: "staging" }),
        /Invalid arguments: projectId/,
      );
      assert.match(
        await callError("invite-members-to-project", { projectId, emails: ["dev@example.com"] }),
        /Invalid arguments: projectId/,
      );
    }
    assert.equal(secretRequests().length, 0);
  });
});

describe("errors", () => {
  test("surfaces an API refusal as a tool error with the API's message", async (t) => {
    const { callError, logs } = await setup(t, {
      respond: ({ path }) =>
        path.startsWith("/api/v4/secrets")
          ? [403, { message: "You are not allowed to read secrets in dev" }]
          : undefined,
    });

    const text = await callError("get-secret", { ...SECRET_LOCATION, secretName: "DB_PASSWORD" });

    assert.match(text, /Infisical API returned 403: You are not allowed to read secrets in dev/);
    assert.ok(!text.includes("Bearer"));
    assert.equal(logs[0].outcome, "error");
  });

  test("shows the reasons for a validation failure", async (t) => {
    // Infisical sends a 422's validation issues as an array in message
    const { callError } = await setup(t, {
      env: ALL_TOOLS,
      respond: ({ method, path }) =>
        method === "POST" && path.startsWith("/api/v4/secrets/")
          ? [422, {
              statusCode: 422,
              error: "ValidationFailure",
              message: [{ code: "custom", message: "Secret name cannot contain colons", path: ["secretName"] }],
            }]
          : undefined,
    });

    const text = await callError("create-secret", { ...SECRET_LOCATION, secretName: "DB:URL", secretValue: SECRET_VALUE });

    assert.match(text, /Infisical API returned 422: .*Secret name cannot contain colons/);
    assert.ok(!text.includes("[object Object]"));
  });

  test("surfaces a list-projects failure as a tool error", async (t) => {
    const { callError } = await setup(t, {
      respond: ({ path }) =>
        path === "/api/v1/workspace" ? [500, { message: "Something broke" }] : undefined,
    });

    assert.match(await callError("list-projects", {}), /Infisical API returned 500: Something broke/);
  });

  test("rejects invalid arguments before calling the API", async (t) => {
    const { callError, secretRequests } = await setup(t);

    assert.match(
      await callError("get-secret", { environmentSlug: "dev", secretName: "DB_PASSWORD" }),
      /Invalid arguments: projectId: Invalid input: expected string, received undefined/,
    );
    assert.equal(secretRequests().length, 0);
  });

  test("rejects secret names that no URL can address", async (t) => {
    const { callError, secretRequests } = await setup(t, { env: ALL_TOOLS });

    for (const secretName of ["", " ", ".", ".."]) {
      for (const tool of ["get-secret", "create-secret", "update-secret", "delete-secret"]) {
        assert.match(
          await callError(tool, { ...SECRET_LOCATION, secretName }),
          /Invalid arguments: secretName/,
          `${tool} accepted ${JSON.stringify(secretName)}`,
        );
      }
    }
    assert.equal(secretRequests().length, 0);
  });

  test("rejects a rename to a name no URL can address", async (t) => {
    const { callError, secretRequests } = await setup(t, { env: ALL_TOOLS });

    for (const newSecretName of ["", ".", ".."]) {
      assert.match(
        await callError("update-secret", { ...SECRET_LOCATION, secretName: "DB_PASSWORD", newSecretName }),
        /Invalid arguments: newSecretName/,
      );
    }
    assert.equal(secretRequests().length, 0);
  });

  test("does not echo a submitted value when a write fails", async (t) => {
    const { callError, logs } = await setup(t, {
      env: ALL_TOOLS,
      respond: ({ method, path }) =>
        method === "POST" && path.startsWith("/api/v4/secrets/")
          ? [400, { message: "Secret already exist" }]
          : undefined,
    });

    const text = await callError("create-secret", {
      ...SECRET_LOCATION,
      secretName: "NEW_KEY",
      secretValue: SECRET_VALUE,
    });

    assert.match(text, /Secret already exist/);
    assert.ok(!text.includes(SECRET_VALUE));
    assert.ok(!JSON.stringify(logs).includes(SECRET_VALUE));
  });
});

describe("requests to Infisical", () => {
  const FAST = { requestTimeoutMs: 50, retryDelayMs: 1 };
  const isListRequest = ({ path }) => path === "/api/v4/secrets";

  test("retries a rate-limited read", async (t) => {
    let limited = 2;
    const { call, secretRequests } = await setup(t, {
      options: FAST,
      respond: (request) =>
        isListRequest(request) && limited-- > 0
          ? [429, { message: "Too many requests" }]
          : undefined,
    });

    const response = JSON.parse(await call("list-secrets", SECRET_LOCATION));

    assert.equal(secretRequests().length, 3);
    assert.equal(response.secrets[0].secretKey, "DB_PASSWORD");
  });

  test("gives up on a read that never answers", async (t) => {
    const { callError, secretRequests } = await setup(t, {
      options: FAST,
      respond: (request) => (isListRequest(request) ? HANG : undefined),
    });

    assert.match(await callError("list-secrets", SECRET_LOCATION), /timeout of 50ms exceeded/);
    // the first attempt and four retries
    assert.equal(secretRequests().length, 5);
  });

  test("does not retry a read Infisical refused", async (t) => {
    const { callError, secretRequests } = await setup(t, {
      options: FAST,
      respond: (request) =>
        isListRequest(request) ? [403, { message: "Forbidden" }] : undefined,
    });

    assert.match(await callError("list-secrets", SECRET_LOCATION), /403: Forbidden/);
    assert.equal(secretRequests().length, 1);
  });

  test("stops a read when the client cancels the call", async (t) => {
    const { client, secretRequests } = await setup(t, {
      respond: (request) => (isListRequest(request) ? HANG : undefined),
    });
    const controller = new AbortController();

    const pending = client.callTool(
      { name: "list-secrets", arguments: SECRET_LOCATION },
      undefined,
      { signal: controller.signal },
    );
    await waitFor(() => secretRequests().length === 1);
    controller.abort();

    await assert.rejects(pending);
    await waitFor(() => secretRequests()[0].closed);
  });

  const NEW_SECRET = { ...SECRET_LOCATION, secretName: "NEW_KEY", secretValue: SECRET_VALUE };
  // the login is a POST too, so match the secret route
  const isSecretWrite = ({ method, path }) =>
    method === "POST" && path.startsWith("/api/v4/secrets/");

  test("does not resend a write that got no response", async (t) => {
    const { callError, secretRequests } = await setup(t, {
      env: ALL_TOOLS,
      options: FAST,
      respond: (request) => (isSecretWrite(request) ? HANG : undefined),
    });

    assert.match(await callError("create-secret", NEW_SECRET), /timeout of 50ms exceeded/);
    // Infisical may have applied it, so sending it again could apply it twice
    assert.equal(secretRequests().length, 1);
  });

  test("does not resend a project write that got no response", async (t) => {
    const { callError, secretRequests } = await setup(t, {
      env: ALL_TOOLS,
      options: FAST,
      respond: ({ method, path }) =>
        method === "POST" && path === "/api/v2/workspace" ? HANG : undefined,
    });

    assert.match(
      await callError("create-project", { projectName: "Billing", type: "secret-manager", slug: "billing" }),
      /timeout of 50ms exceeded/,
    );
    // a second POST could create the project twice, or report it as a conflict
    assert.equal(secretRequests().length, 1);
  });

  test("retries a rate-limited write", async (t) => {
    let limited = 1;
    const { call, secretRequests } = await setup(t, {
      env: ALL_TOOLS,
      options: FAST,
      respond: (request) =>
        isSecretWrite(request) && limited-- > 0
          ? [429, { message: "Too many requests" }]
          : undefined,
    });

    await call("create-secret", NEW_SECRET);

    assert.equal(secretRequests().length, 2);
  });

  test("lets a write finish, and records it, when the client cancels", async (t) => {
    const { client, logs, secretRequests } = await setup(t, {
      env: ALL_TOOLS,
      respond: (request) => (isSecretWrite(request) ? HANG : undefined),
    });
    const controller = new AbortController();

    const pending = client.callTool(
      { name: "create-secret", arguments: NEW_SECRET },
      undefined,
      { signal: controller.signal },
    );
    await waitFor(() => secretRequests().length === 1);
    controller.abort();
    await assert.rejects(pending);

    const [request] = secretRequests();
    assert.ok(!request.closed);
    request.respond(200, { secret: { secretKey: "NEW_KEY", secretValue: SECRET_VALUE } });

    await waitFor(() => logs.length === 1);
    assert.equal(logs[0].outcome, "success");
  });

  // starts a call, cancels it once its first request reaches the API, and
  // waits for the server to finish with it
  const cancelAfterFirstRequest = async ({ client, logs }, name, args, isRequest, api) => {
    const controller = new AbortController();
    const pending = client.callTool({ name, arguments: args }, undefined, { signal: controller.signal });
    await waitFor(() => api.requests.some(isRequest));
    controller.abort();
    await assert.rejects(pending);
    return api.requests.find(isRequest);
  };

  test("does not log in again and resend a cancelled write that got a 401", async (t) => {
    const context = await setup(t, {
      env: ALL_TOOLS,
      respond: (request) => (isSecretWrite(request) ? HANG : undefined),
    });
    await context.call("list-secrets", SECRET_LOCATION);

    const write = await cancelAfterFirstRequest(context, "create-secret", NEW_SECRET, isSecretWrite, context.api);
    // refused before anything was applied, so a resend would be a new write
    write.respond(401, { message: "Token revoked" });
    await waitFor(() => context.logs.length === 2);

    assert.equal(context.api.requests.filter(isSecretWrite).length, 1);
    assert.equal(context.logins().length, 1);
  });

  test("does not resend a rate-limited write after the client cancels", async (t) => {
    const context = await setup(t, {
      env: ALL_TOOLS,
      options: { retryDelayMs: 200 },
      respond: (request) => (isSecretWrite(request) ? [429, { message: "Too many requests" }] : undefined),
    });

    await cancelAfterFirstRequest(context, "create-secret", NEW_SECRET, isSecretWrite, context.api);
    await waitFor(() => context.logs.length === 1);
    // past the backoff, when a resend would have gone out
    await new Promise((resolve) => setTimeout(resolve, 400));

    assert.equal(context.api.requests.filter(isSecretWrite).length, 1);
  });

  test("stops waiting to retry a read when the client cancels", async (t) => {
    const context = await setup(t, {
      options: { retryDelayMs: 1000 },
      respond: (request) => (isListRequest(request) ? [429, { message: "Too many requests" }] : undefined),
    });

    await cancelAfterFirstRequest(context, "list-secrets", SECRET_LOCATION, isListRequest, context.api);
    const cancelledAt = Date.now();
    await waitFor(() => context.logs.length === 1);

    // well inside the first backoff of about a second
    assert.ok(Date.now() - cancelledAt < 500, `took ${Date.now() - cancelledAt}ms`);
  });
});

describe("authentication", () => {
  test("logs in once and sends the token on every request", async (t) => {
    const { call, api, logins } = await setup(t);

    await call("list-secrets", SECRET_LOCATION);
    await call("get-secret", { ...SECRET_LOCATION, secretName: "DB_PASSWORD" });
    await call("list-projects", {});

    assert.equal(logins().length, 1);
    assert.equal(logins()[0].body.clientSecret, CLIENT_SECRET);

    const [, ...calls] = api.requests;
    assert.equal(calls.length, 3);
    assert.ok(calls.every((request) => /^Bearer .+\..+\..+$/.test(request.authorization)));
  });

  // the clock is mocked so a token can age without the test waiting. logins
  // and renewals both issue a token with the given lifetime, unless `respond`
  // answers them first
  const withTokenLifetime = async (t, ttlSeconds, respond) => {
    t.mock.timers.enable({ apis: ["Date"], now: Date.now() });
    return setup(t, {
      respond: (request) => {
        const response = respond?.(request);
        if (response) return response;
        if (request.path === LOGIN_PATH) {
          return [200, { accessToken: accessToken(ttlSeconds), expiresIn: ttlSeconds }];
        }
        if (request.path === RENEW_PATH) {
          return [200, { accessToken: request.body.accessToken, expiresIn: ttlSeconds }];
        }
      },
    });
  };

  test("keeps a token until a minute before it expires, then renews it", async (t) => {
    const { call, logins, renewals, secretRequests } = await withTokenLifetime(t, 3600);

    await call("list-secrets", SECRET_LOCATION);
    t.mock.timers.tick((3600 - 61) * 1000);
    await call("list-secrets", SECRET_LOCATION);
    assert.equal(renewals().length, 0);

    t.mock.timers.tick(2 * 1000);
    await call("list-secrets", SECRET_LOCATION);
    assert.equal(renewals().length, 1);
    // renewing spends none of the client secret's uses, as a login would
    assert.equal(logins().length, 1);
    assert.equal(`Bearer ${renewals()[0].body.accessToken}`, secretRequests()[0].authorization);
    assert.equal(renewals()[0].authorization, undefined);
  });

  test("renews a short-lived token halfway through, not on every call", async (t) => {
    const { call, logins, renewals } = await withTokenLifetime(t, 30);

    await call("list-secrets", SECRET_LOCATION);
    await call("list-secrets", SECRET_LOCATION);
    t.mock.timers.tick(14 * 1000);
    await call("list-secrets", SECRET_LOCATION);
    assert.equal(renewals().length, 0);

    t.mock.timers.tick(2 * 1000);
    await call("list-secrets", SECRET_LOCATION);
    assert.equal(renewals().length, 1);
    assert.equal(logins().length, 1);
  });

  test("logs in again once Infisical refuses to renew the token", async (t) => {
    const { call, logins, renewals } = await withTokenLifetime(t, 3600, ({ path }) =>
      path === RENEW_PATH
        ? [401, { message: "Cannot renew: identity access token has reached its max TTL" }]
        : undefined,
    );

    await call("list-secrets", SECRET_LOCATION);
    t.mock.timers.tick((3600 - 59) * 1000);
    await call("list-secrets", SECRET_LOCATION);

    assert.equal(renewals().length, 1);
    assert.equal(logins().length, 2);
  });

  test("keeps a token that still works when renewing and logging in both fail", async (t) => {
    let infisicalDown = false;
    const { call, callError, logs, secretRequests } = await withTokenLifetime(t, 3600, ({ path }) =>
      infisicalDown && path.includes("/auth/") ? [502, { message: "Bad gateway" }] : undefined,
    );

    await call("list-secrets", SECRET_LOCATION);
    const token = secretRequests()[0].authorization;
    infisicalDown = true;

    t.mock.timers.tick((3600 - 59) * 1000);
    await call("list-secrets", SECRET_LOCATION);
    assert.equal(secretRequests()[1].authorization, token);
    assert.ok(logs.some((entry) => entry.event === "token_renewal_failed"));

    // once it has expired there is nothing left to fall back on
    t.mock.timers.tick(60 * 1000);
    assert.match(await callError("list-secrets", SECRET_LOCATION), /502: Bad gateway/);
  });

  test("retries a login that got no response", async (t) => {
    let hung = false;
    const { call, logins } = await setup(t, {
      options: { requestTimeoutMs: 50, retryDelayMs: 1 },
      respond: (request) => {
        if (request.path === LOGIN_PATH && !hung) {
          hung = true;
          return HANG;
        }
      },
    });

    await call("list-secrets", SECRET_LOCATION);

    assert.equal(logins().length, 2);
  });

  test("shares one login between calls that arrive together", async (t) => {
    const { call, logins } = await setup(t);

    await Promise.all(
      Array.from({ length: 5 }, () => call("list-secrets", SECRET_LOCATION)),
    );

    assert.equal(logins().length, 1);
  });

  // issues a distinct token per login, and once revoke() is called rejects
  // the tokens issued so far, as Infisical does once a token is revoked or
  // runs out of uses. like Infisical, it checks a token sent with any request,
  // the login included
  const revocableTokens = () => {
    const issued = [];
    const revoked = new Set();
    return {
      revoke: () => issued.forEach((token) => revoked.add(token)),
      respond: (request) => {
        if (revoked.has(request.authorization?.replace("Bearer ", ""))) {
          return [401, { message: "Failed to authorize: token usage limit reached" }];
        }
        if (request.path === LOGIN_PATH) {
          const token = `${accessToken(3600)}.${issued.length}`;
          issued.push(token);
          return [200, { accessToken: token, expiresIn: 3600 }];
        }
      },
    };
  };

  test("logs in again when Infisical rejects the token, and retries the read", async (t) => {
    const tokens = revocableTokens();
    const { call, logins, secretRequests } = await setup(t, { respond: tokens.respond });

    await call("list-secrets", SECRET_LOCATION);
    tokens.revoke();
    const text = await call("get-secret", { ...SECRET_LOCATION, secretName: "DB_PASSWORD" });

    assert.equal(parseResponse(text).secretKey, "DB_PASSWORD");
    assert.equal(logins().length, 2);
    // the list, the refused get, and the get retried with the new token
    assert.equal(secretRequests().length, 3);
  });

  test("recovers every call that arrives together with a revoked token", async (t) => {
    const tokens = revocableTokens();
    const { call, logins } = await setup(t, { respond: tokens.respond });

    await call("list-secrets", SECRET_LOCATION);
    tokens.revoke();
    await Promise.all(
      Array.from({ length: 3 }, () => call("list-secrets", SECRET_LOCATION)),
    );

    // one login for all three, not one each
    assert.equal(logins().length, 2);
  });

  test("logs in again when a project tool gets a 401", async (t) => {
    const tokens = revocableTokens();
    const { call, logins } = await setup(t, { env: ALL_TOOLS, respond: tokens.respond });

    await call("list-secrets", SECRET_LOCATION);
    tokens.revoke();
    await call("create-folder", { projectId: "project-1", environment: "dev", name: "backend" });

    assert.equal(logins().length, 2);
  });

  test("retries a direct write after a 401", async (t) => {
    const tokens = revocableTokens();
    const { call, logins, secretRequests } = await setup(t, {
      env: ALL_TOOLS,
      respond: tokens.respond,
    });

    await call("list-secrets", SECRET_LOCATION);
    tokens.revoke();
    const text = await call("create-secret", {
      ...SECRET_LOCATION,
      secretName: "NEW_KEY",
      secretValue: SECRET_VALUE,
    });

    assert.match(text, /Secret created successfully/);
    assert.equal(logins().length, 2);
    const creates = secretRequests().filter((request) => request.method === "POST");
    assert.equal(creates.length, 2);
  });

  test("gives up when the new token is rejected too", async (t) => {
    const { callError, logins } = await setup(t, {
      respond: ({ path }) =>
        path.startsWith("/api/v4/secrets") ? [401, { message: "Token revoked" }] : undefined,
    });

    assert.match(await callError("list-secrets", SECRET_LOCATION), /401: Token revoked/);
    // the first call's own login, and no retry, since its token was fresh
    assert.equal(logins().length, 1);

    assert.match(await callError("list-secrets", SECRET_LOCATION), /401: Token revoked/);
    // one more login for the retry, then it gives up
    assert.equal(logins().length, 2);
  });

  test("does not log in twice when the login itself is refused", async (t) => {
    const { callError, logins } = await setup(t, {
      respond: ({ path }) =>
        path.includes("/auth/") ? [401, { message: "Invalid credentials" }] : undefined,
    });

    assert.match(await callError("list-secrets", SECRET_LOCATION), /Invalid credentials/);
    assert.equal(logins().length, 1);
  });

  test("does not retry a rejected access token it cannot renew", async (t) => {
    let expired = false;
    const { call, callError, api } = await setup(t, {
      env: { INFISICAL_AUTH_METHOD: "access-token", INFISICAL_TOKEN: "configured-token" },
      respond: () => (expired ? [401, { message: "Token expired" }] : undefined),
    });

    await call("list-secrets", SECRET_LOCATION);
    expired = true;
    assert.match(await callError("list-secrets", SECRET_LOCATION), /401: Token expired/);

    assert.equal(api.requests.length, 2);
  });

  test("sends its name and version as the user agent", async (t) => {
    const { call, api } = await setup(t);
    const userAgent = `infisical-mcp-server/${require("../package.json").version}`;

    await call("list-secrets", SECRET_LOCATION);

    assert.deepEqual(api.requests.map((request) => request.userAgent), [userAgent, userAgent]);
  });

  test("uses a configured access token without logging in", async (t) => {
    const { call, api } = await setup(t, {
      env: { INFISICAL_AUTH_METHOD: "access-token", INFISICAL_TOKEN: "configured-token" },
    });

    await call("list-secrets", SECRET_LOCATION);

    assert.equal(api.requests.length, 1);
    assert.equal(api.requests[0].authorization, "Bearer configured-token");
  });
});

describe("audit log", () => {
  test("records who called which tool on what, and never a secret", async (t) => {
    const { call, logs } = await setup(t, { env: ALL_TOOLS });

    await call("create-secret", {
      ...SECRET_LOCATION,
      secretName: "NEW_KEY",
      secretValue: SECRET_VALUE,
    });
    await call("get-secret", { ...SECRET_LOCATION, secretName: "NEW_KEY" });

    assert.equal(logs.length, 2);
    assert.deepEqual(
      { ...logs[0], durationMs: undefined },
      {
        level: "info",
        event: "tool_call",
        tool: "create-secret",
        outcome: "success",
        durationMs: undefined,
        actor: { authMethod: "universal-auth", clientId: "universal-auth-client-id" },
        client: { name: "test-client", version: "1.0.0" },
        arguments: { projectId: "project-1", environmentSlug: "dev", secretName: "NEW_KEY" },
      },
    );
    assert.equal(typeof logs[0].durationMs, "number");

    const written = JSON.stringify(logs);
    assert.ok(!written.includes(SECRET_VALUE));
    assert.ok(!written.includes(CLIENT_SECRET));
    assert.ok(!written.includes("Bearer"));
  });

  test("records an unknown tool as an error, not as denied", async (t) => {
    const { call, logs } = await setup(t, { env: ALL_TOOLS });

    await assert.rejects(call("read-minds", {}));

    assert.equal(logs[0].outcome, "error");
    assert.equal(logs[0].level, "error");
  });

  test("does not fail a call that worked when the entry cannot be written", async (t) => {
    const { call, secretRequests } = await setup(t, {
      env: ALL_TOOLS,
      options: {
        log: () => {
          throw new Error("No space left on device");
        },
      },
    });

    const text = await call("create-secret", {
      ...SECRET_LOCATION,
      secretName: "NEW_KEY",
      secretValue: SECRET_VALUE,
    });

    assert.match(text, /Secret created successfully/);
    assert.equal(secretRequests().length, 1);
  });

  test("warns at startup about each hardening control left off", () => {
    const entry = getStartupLogEntry(
      getEnvironmentVariables({ INFISICAL_AUTH_METHOD: "access-token", INFISICAL_TOKEN: "token" }),
    );

    assert.equal(entry.level, "warn");
    assert.equal(entry.warnings.length, 2);
    assert.match(entry.warnings[0], /INFISICAL_MASK_SECRET_VALUES=true/);
    assert.match(entry.warnings[1], /create-secret, delete-secret, update-secret/);
  });

  test("starts without warnings when both hardening controls are on", () => {
    const entry = getStartupLogEntry(
      getEnvironmentVariables({
        INFISICAL_AUTH_METHOD: "access-token",
        INFISICAL_TOKEN: "token",
        ...READ_ONLY,
        ...MASKED,
      }),
    );

    assert.equal(entry.level, "info");
    assert.ok(!("warnings" in entry));
  });

  test("can be turned off", async (t) => {
    const { call, logs } = await setup(t, { env: { INFISICAL_AUDIT_LOG: "false" } });

    await call("list-secrets", SECRET_LOCATION);

    assert.equal(logs.length, 0);
  });
});

// the stdio entry point only runs as its own process, so this one test
// starts the built server the way an MCP client does
describe("the stdio server", () => {
  test("keeps serving after the client closes its stderr", async (t) => {
    const api = await startApi();
    t.after(() => api.close());

    const child = spawn(process.execPath, [path.join(__dirname, "../dist/index.js")], {
      env: {
        PATH: process.env.PATH,
        INFISICAL_AUTH_METHOD: "access-token",
        INFISICAL_TOKEN: "token",
        INFISICAL_HOST_URL: api.url,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    t.after(() => child.kill());

    const responses = new Map();
    readline.createInterface({ input: child.stdout }).on("line", (line) => {
      const message = JSON.parse(line);
      responses.get(message.id)?.(message);
    });
    const request = (id, method, params = {}) =>
      new Promise((resolve, reject) => {
        responses.set(id, resolve);
        child.once("exit", (code) => reject(new Error(`server exited with ${code}`)));
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      });

    // the client stops reading stderr once the server starts logging to it
    await new Promise((resolve) => child.stderr.once("data", resolve));
    child.stderr.destroy();

    await request(1, "initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "test-client", version: "1.0.0" },
    });
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
    // writes an audit entry to the closed stderr
    await request(2, "tools/call", { name: "list-secrets", arguments: SECRET_LOCATION });
    const { result } = await request(3, "tools/list");

    assert.equal(result.tools.length, 10);
  });
});
