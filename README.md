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

By default every tool is exposed and secret values are returned, as in earlier versions. [Limiting what the server exposes](#limiting-what-the-server-exposes) explains how to restrict both, which we recommend, and [Audit log](#audit-log) covers what the server records.

To run the Infisical MCP server using npx, use the following command:

```bash
npx -y @infisical/mcp
```

### Usage with Claude Desktop

Add the following to your `claude_desktop_config.json`. See [here](https://modelcontextprotocol.io/quickstart/user) for more details.

#### Universal Auth (default)

```json
{
  "mcpServers": {
    "infisical": {
      "command": "npx",
      "args": ["-y", "@infisical/mcp"],
      "env": {
        "INFISICAL_HOST_URL": "https://<custom-host-url>.com",
        "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": "<machine-identity-universal-auth-client-id>",
        "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "<machine-identity-universal-auth-client-secret>"
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

| Tool                        | Description                             | Read-only |
| --------------------------- | --------------------------------------- | --------- |
| `create-secret`             | Create a new secret                     | No        |
| `delete-secret`             | Delete a secret                         | No        |
| `update-secret`             | Update a secret                         | No        |
| `list-secrets`              | Lists all secrets                       | Yes       |
| `get-secret`                | Get a single secret                     | Yes       |
| `create-project`            | Create a new project                    | No        |
| `create-environment`        | Create a new environment                | No        |
| `create-folder`             | Create a new folder                     | No        |
| `invite-members-to-project` | Invite one or more members to a project | No        |
| `list-projects`             | List all projects                       | Yes       |

## Limiting what the server exposes

Two optional variables restrict the server. Both default to the behaviour of earlier versions, so existing setups keep working. We recommend setting both wherever the model does not need to change anything or read secret values.

- `INFISICAL_ENABLED_TOOLS`: a comma-separated allowlist of tools to expose, using the tool names from the table above. Omit it, or set it to `all`, to expose every tool. For a read-only server, list the read-only tools: `list-projects,list-secrets,get-secret`. Tools left out are hidden from `tools/list` and refused if called. An unknown name fails at startup, and so does an empty value.
- `INFISICAL_MASK_SECRET_VALUES`: `true` or `false`, case-insensitive. Defaults to `false`. When `true`, secret values in tool responses are replaced with `<masked>`, and `list-secrets` and `get-secret` ask Infisical not to send the values at all, so on Infisical Cloud and self-hosted v0.116.0 or later they never reach the server or the model. Secret names, paths, and other metadata are still returned.

A hardened configuration sets both:

```json
"env": {
  "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": "<machine-identity-universal-auth-client-id>",
  "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "<machine-identity-universal-auth-client-secret>",
  "INFISICAL_ENABLED_TOOLS": "list-projects,list-secrets,get-secret",
  "INFISICAL_MASK_SECRET_VALUES": "true"
}
```

Scope the machine identity to only the projects and environments the server needs, rather than using a token with broader access than the exposed tools require.

### Upgrading

Existing configurations keep working. Two things behave differently from earlier versions:

- A tool that fails while running, for example because Infisical refused the request, returns a result with `isError` set and the reason as its text, instead of a JSON-RPC error. Calling an unknown or disabled tool is still a JSON-RPC error.
- The secret tools use Infisical's v4 secrets API. A self-hosted version before v0.150.0 has none, and on one the server switches to the deprecated v3 routes by itself.

## Audit log

The server writes one JSON object per line to stderr: a `server_started` entry with the version, host, enabled tools and masking setting, logged as a warning that names any hardening control left off, then a `tool_call` entry for every call. It also logs a `secrets_api_fallback` warning, once, when the instance has no v4 secrets API or answers it with a 404 page, and a `token_renewal_failed` warning when it could neither renew the access token nor log in again and keeps using the current token until it expires. MCP clients usually keep a server's stderr in their logs; Claude Desktop, for example, writes it to `mcp-server-infisical.log`. Each `tool_call` entry records:

- `time`, `tool`, `durationMs`, and `outcome`: `success`, `pending_approval` when the change is waiting for approval, `error`, or `denied` when the tool is not enabled.
- `actor`: the authentication method and, for universal auth, the machine identity's client ID.
- `client`: the name and version the MCP client reported when it connected.
- `arguments`: identifiers only, such as project ID, environment, path, secret name, and the members and roles of an invite.
- `error`: the error message, when the call failed.

Secret values, the client secret and access tokens are never written. Set `INFISICAL_AUDIT_LOG=false` to turn off the `tool_call` entries.

Infisical's own audit log records every secret operation as well, with the machine identity as the actor. Listing projects is the one call it does not record.

## Security and operations

### Network access

The server talks to its MCP client over stdio and opens no ports. Its only outbound traffic is HTTPS to `INFISICAL_HOST_URL`, and it sends no telemetry. Requests follow the standard `HTTPS_PROXY` and `NO_PROXY` variables if they are set. The endpoints it calls are:

| Endpoint                                              | Used by                                                         |
| ----------------------------------------------------- | --------------------------------------------------------------- |
| `POST /api/v1/auth/universal-auth/login`              | Universal auth login                                            |
| `GET /api/v4/secrets`                                 | `list-secrets`                                                  |
| `GET, POST, PATCH, DELETE /api/v4/secrets/{name}`     | `get-secret`, `create-secret`, `update-secret`, `delete-secret` |
| `/api/v3/secrets/raw`, `/api/v3/secrets/raw/{name}`   | The same tools, on self-hosted versions before v0.150.0         |
| `GET /api/v1/workspace`                               | `list-projects`                                                 |
| `POST /api/v2/workspace`                              | `create-project`                                                |
| `POST /api/v1/workspace/{projectId}/environments`     | `create-environment`                                            |
| `POST /api/v1/folders`                                | `create-folder`                                                 |
| `POST /api/v2/workspace/{projectId}/memberships`      | `invite-members-to-project`                                     |

Launching through `npx` also contacts the npm registry to fetch the package. To avoid that at runtime, install a pinned version ahead of time and point the client at it.

### Scoping the machine identity

The server enforces no permissions of its own. It can do whatever its identity can do, and Infisical enforces that on every call, so scope the identity rather than relying on the tool allowlist alone.

- Prefer a machine identity with universal auth over a personal access token, which carries everything its user can do.
- Add the identity only to the projects it needs, with a custom role limited to the environments and secret paths in question.
- With masking on, `list-secrets` and `get-secret` only need the Describe Secret permission, on Infisical Cloud or self-hosted v0.116.0 or later. Grant Read Value only if you turn masking off.
- Grant create, edit or delete on secrets, or permission to manage projects and members, only if you enable the tools that need them.
- Restrict where the identity can be used from with the client secret's and access token's trusted IPs.

### Rotating credentials

- **Universal auth.** Create a new client secret on the identity, update `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` in the client's configuration, restart the client, then revoke the old secret. A short access token TTL is fine: the server renews the token shortly before it expires, and logs in again only once Infisical refuses to renew it, at the token's max TTL, so it does not need a restart when one lapses. Renewing spends none of the client secret's uses; each login spends one when the secret has a usage limit.
- **Access token.** The server cannot renew a token passed in `INFISICAL_TOKEN`. When it expires or is rotated, update the configuration and restart the client.

### Pinning, verifying and rolling back

`npx -y @infisical/mcp` runs the latest release. To control when upgrades happen, pin a version in the client's configuration:

```json
"args": ["-y", "@infisical/mcp@0.0.25"]
```

To roll back, pin the previous version and restart the client. Release notes are on the repository's [Releases](https://github.com/Infisical/infisical-mcp-server/releases) page.

Each release is published from GitHub Actions through npm trusted publishing, with a provenance attestation naming the repository, workflow and tag it was built from. To check it, run `npm audit signatures` in a project with the package installed.

The package ships `npm-shrinkwrap.json`, so an install gets exactly the dependency versions the release was tested with, and `sbom.cdx.json`, a CycloneDX SBOM of those dependencies. The SBOM is also attached to each GitHub release.

Every pull request is checked by Socket for risky dependency changes, and by CodeQL for security issues in the code and workflows. CI fails on a high or critical advisory in a runtime dependency, or a package whose registry signature does not verify.

Until 1.0, a change to a default ships in a new minor version, never in a patch release. Each release's notes list any change in behaviour.

### Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Please do not open a public issue for a security problem.

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
