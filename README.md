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

By default the server only exposes the tools that read, and masks secret values. See [Limiting what the server exposes](#limiting-what-the-server-exposes) to change either.

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
