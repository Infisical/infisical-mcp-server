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

By default the server only exposes the tools that read, masks secret values, and logs each tool call to stderr. See [Limiting what the server exposes](#limiting-what-the-server-exposes) and [Audit log](#audit-log) to change these.

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

| Tool                        | Description                             | Enabled by default |
| --------------------------- | --------------------------------------- | ------------------ |
| `create-secret`             | Create a new secret                     | No                 |
| `delete-secret`             | Delete a secret                         | No                 |
| `update-secret`             | Update a secret                         | No                 |
| `list-secrets`              | Lists all secrets                       | Yes                |
| `get-secret`                | Get a single secret                     | Yes                |
| `create-project`            | Create a new project                    | No                 |
| `create-environment`        | Create a new environment                | No                 |
| `create-folder`             | Create a new folder                     | No                 |
| `invite-members-to-project` | Invite one or more members to a project | No                 |
| `list-projects`             | List all projects                       | Yes                |

## Limiting what the server exposes

The server starts locked down: it exposes only the tools that read, and masks secret values. Two optional variables change that.

- `INFISICAL_ENABLED_TOOLS`: a comma-separated allowlist of tools to expose, using the tool names from the table above. Defaults to `list-projects,list-secrets,get-secret`. Set it to `all` to expose every tool, or list the ones you need, for example `list-projects,list-secrets,get-secret,create-secret`. Tools left out are hidden from `tools/list` and refused if called. An unknown name fails at startup, and so does an empty value.
- `INFISICAL_MASK_SECRET_VALUES`: `true` or `false`, case-insensitive. Defaults to `true`, which replaces secret values in tool responses with `<masked>`. For `list-secrets` and `get-secret` it also asks Infisical not to send values at all, so they never reach the server or the model. Secret names, paths, and other metadata are still returned. Set it to `false` only if the model needs to read secret values.

Scope the machine identity to only the projects and environments the server needs, rather than using a token with broader access than the exposed tools require.

### Upgrading from 0.0.x

Version 0.1.0 changes both defaults. Earlier versions exposed every tool and returned secret values unless told otherwise. To keep that behaviour, set both variables explicitly:

```json
"env": {
  "INFISICAL_ENABLED_TOOLS": "all",
  "INFISICAL_MASK_SECRET_VALUES": "false"
}
```

## Audit log

The server writes one JSON object per line to stderr: a `server_started` entry with the version, host, enabled tools and masking setting, then a `tool_call` entry for every call. MCP clients usually keep a server's stderr in their logs; Claude Desktop, for example, writes it to `mcp-server-infisical.log`. Each `tool_call` entry records:

- `time`, `tool`, `durationMs`, and `outcome`: `success`, `error`, or `denied` when the tool is not enabled.
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
| `GET /api/v3/secrets/raw`                             | `list-secrets`                                                  |
| `GET, POST, PATCH, DELETE /api/v3/secrets/raw/{name}` | `get-secret`, `create-secret`, `update-secret`, `delete-secret` |
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
- With masking on, `list-secrets` and `get-secret` only need the Describe Secret permission. Grant Read Value only if you turn masking off.
- Grant create, edit or delete on secrets, or permission to manage projects and members, only if you enable the tools that need them.
- Restrict where the identity can be used from with the client secret's and access token's trusted IPs.

### Rotating credentials

- **Universal auth.** Create a new client secret on the identity, update `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET` in the client's configuration, restart the client, then revoke the old secret. A short access token TTL is fine: the server logs in again shortly before each token expires, so it does not need a restart when one lapses.
- **Access token.** The server cannot renew a token passed in `INFISICAL_TOKEN`. When it expires or is rotated, update the configuration and restart the client.

### Pinning, verifying and rolling back

`npx -y @infisical/mcp` runs the latest release. To control when upgrades happen, pin a version in the client's configuration:

```json
"args": ["-y", "@infisical/mcp@0.1.0"]
```

To roll back, pin the previous version and restart the client. Release notes are on the repository's [Releases](https://github.com/Infisical/infisical-mcp-server/releases) page.

Each release is published from GitHub Actions through npm trusted publishing, with a provenance attestation naming the repository, workflow and tag it was built from. To check it, run `npm audit signatures` in a project with the package installed.

The package ships `npm-shrinkwrap.json`, so an install gets exactly the dependency versions the release was tested with, and `sbom.cdx.json`, a CycloneDX SBOM of those dependencies. The SBOM is also attached to each GitHub release.

Releases follow semantic versioning. While the version is below 1.0, a minor release, such as 0.1.0, may change defaults or behaviour, and a patch release only fixes problems.

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
