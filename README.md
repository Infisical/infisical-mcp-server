# Infisical Model Context Protocol

The Infisical [Model Context Protocol](https://modelcontextprotocol.io/) server allows you to integrate with Infisical APIs through function calling. This protocol supports various tools to interact with Infisical.

## Setup

### Environment variables

In order to use the MCP server, you must first set the environment variables required for authentication.

- `INFISICAL_AUTH_METHOD`: The authentication method to use. Supported values are `universal-auth` and `access-token`. Defaults to `universal-auth`.
- `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID`: The Machine Identity universal auth client ID. Required when `INFISICAL_AUTH_METHOD` is `universal-auth`.
- `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET`: The Machine Identity universal auth client secret. Required when `INFISICAL_AUTH_METHOD` is `universal-auth`.
- `INFISICAL_TOKEN`: An access token for authentication. This can be both a personal access token or a machine identity access token. Required when `INFISICAL_AUTH_METHOD` is `access-token`.
- `INFISICAL_HOST_URL`: **Optionally** set a custom host URL. This is useful if you're self-hosting Infisical or you're on dedicated infrastructure. Defaults to `https://app.infisical.com`.
- `INFISICAL_MCP_VALUE_ACCESS`: **Security gate.** Controls whether this MCP instance can return secret values. Set to `enabled` to allow `list-secrets` to expose values (via per-call `includeValues=true`) and to allow `get-secret` to return values. Leave unset or set to any other value to mask all values. **Default: disabled** (safe). See [Security](#security-secret-value-access) for details.

To run the Infisical MCP server using npx, use the following command:

```bash
npx -y @infisical/mcp
```

### Usage with Claude Desktop

Add the following to your `claude_desktop_config.json`. See [here](https://modelcontextprotocol.io/quickstart/user) for more details.

#### Universal Auth (default)

The default configuration masks all secret values. To opt in to value reads (not recommended for production), set `INFISICAL_MCP_VALUE_ACCESS=enabled`. See [Security](#security-secret-value-access) for details.

```json
{
  "mcpServers": {
    "infisical": {
      "command": "npx",
      "args": ["-y", "@infisical/mcp"],
      "env": {
        "INFISICAL_HOST_URL": "https://<custom-host-url>.com",
        "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": "<machine-identity-universal-auth-client-id>",
        "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "<machine-identity-universal-auth-client-secret>",
        "INFISICAL_MCP_VALUE_ACCESS": "disabled"
      }
    }
  }
}
```

#### Access Token

```json
{
  "mcpServers": {
    "infisical": {
      "command": "npx",
      "args": ["-y", "@infisical/mcp"],
      "env": {
        "INFISICAL_HOST_URL": "https://<custom-host-url>.com",
        "INFISICAL_AUTH_METHOD": "access-token",
        "INFISICAL_TOKEN": "<your-access-token>"
      }
    }
  }
}
```

## Available tools

| Tool                        | Description                             |
| --------------------------- | --------------------------------------- |
| `create-secret`             | Create a new secret                     |
| `delete-secret`             | Delete a secret                         |
| `update-secret`             | Update a secret                         |
| `list-secrets`              | Lists all secrets                       |
| `get-secret`                | Get a single secret                     |
| `create-project`            | Create a new project                    |
| `create-environment`        | Create a new environment                |
| `create-folder`             | Create a new folder                     |
| `invite-members-to-project` | Invite one or more members to a project |
| `list-projects`             | List all projects                       |

## Security: Secret value access

Secret values are **masked by default**. This is enforced at the server level, not just by convention, so an LLM client cannot expose values without an explicit operator opt-in.

### How the gate works

The `INFISICAL_MCP_VALUE_ACCESS` environment variable controls whether this MCP instance is *capable* of returning secret values at all. It is independent from any per-call tool parameter.

| `INFISICAL_MCP_VALUE_ACCESS` | Behavior                                                                                                                                  |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| unset / `disabled` / any other value (default) | `list-secrets`: `includeValues` parameter is stripped from the tool schema and any caller-supplied value is ignored — response contains only `secretKey`. `get-secret`: rejects all calls with an error. |
| `enabled`                    | `list-secrets`: `includeValues` parameter is exposed (defaults to `false`). `get-secret`: returns the value as normal. The model still must opt in per call. |

The check is strict — only the literal string `enabled` flips the gate. Anything else is treated as disabled.

### Why two layers (capability + per-call)?

- The **capability flag** (`INFISICAL_MCP_VALUE_ACCESS`) is operator-controlled and lives in deployment config. It answers: *can this MCP instance return values at all?*
- The **per-call parameter** (`includeValues` on `list-secrets`) is caller-controlled. It answers: *does this specific call need values?*

A response only includes values when **both** are true. This means even an operator who enabled the capability still has the model default to masking, and a single careless call cannot exfiltrate values unless the operator explicitly opted in at startup.

### What this protects against

- A model that hallucinates `includeValues=true` — the parameter is stripped from the schema when the capability is disabled, so the LLM has no reason to try, and the handler force-masks as a second line of defense.
- A client that constructs tool calls programmatically with `includeValues=true` — same protection, since the Zod schema rejects unknown properties on the capability-disabled path.
- A future caller (human or agent) who calls `get-secret` directly — the handler rejects the call before reaching the Infisical API.

### What this does NOT protect against

- An Infisical identity (machine identity or PAT) that has read access to secret values. The MCP is only as locked down as its credentials. If the underlying token can read values at the API level, an attacker who bypasses this MCP can still use it directly. Pair this MCP with a keys-only scoped identity for defense in depth.
- Network-level leakage (logs, traces, telemetry). Once a value reaches the response body, anything downstream of it is on its own.

### Recommended posture

For production / shared MCP instances: leave `INFISICAL_MCP_VALUE_ACCESS` unset or set to `disabled`. If a caller needs to verify a value, have them paste a masked confirmation (e.g. first 4 + last 4 chars) directly — do not route value reads through the MCP.

For disposable debug sessions: set `INFISICAL_MCP_VALUE_ACCESS=enabled`, restart the MCP, do your work, then revert. Do not leave this enabled on any MCP instance that has access to projects holding bearer tokens, API keys, or other high-sensitivity material.

## Debugging the Server

To debug your server, you can use the [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector).

First build the server

```bash
npm run build
```

Run the following command in your terminal:

```bash
# Start MCP Inspector and server
npx @modelcontextprotocol/inspector node dist/index.js
```

### Instructions

1. Set the environment variables as described in the [Environment Variables ](#environment-variables) step.
2. Run the command to start the MCP Inspector.
3. Open the MCP Inspector UI in your browser and click Connect to start the MCP server.
4. You can see all the available tools and test them individually.
