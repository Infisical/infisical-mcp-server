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
- `MCP_TRANSPORT`: The transport to use. Supported values are `stdio` and `streamable-http`. Defaults to `stdio`.
- `MCP_HTTP_HOST`: Host interface for `streamable-http` mode. Defaults to `127.0.0.1`.
- `MCP_HTTP_PORT`: Port for `streamable-http` mode. Defaults to `3333`.
- `MCP_HTTP_PATH`: HTTP path for `streamable-http` mode. Defaults to `/mcp`.
- `MCP_HTTP_BODY_LIMIT_BYTES`: Maximum accepted HTTP request body size in `streamable-http` mode. Defaults to `4194304` (4 MiB).
- `MCP_HTTP_SESSION_TTL_MS`: Idle session TTL in `streamable-http` mode. Defaults to `300000` (5 minutes).

To run the Infisical MCP server using npx, use the following command:

```bash
npx -y @infisical/mcp
```

### Streamable HTTP mode

To run the server over Streamable HTTP instead of stdio:

```bash
MCP_TRANSPORT=streamable-http MCP_HTTP_PORT=3333 node dist/index.js
```

The server exposes:

- MCP endpoint: `http://127.0.0.1:3333/mcp`
- Health endpoint: `http://127.0.0.1:3333/health`

This implementation uses the official `StreamableHTTPServerTransport` from
`@modelcontextprotocol/sdk` and keeps stdio as the default for compatibility.
Idle HTTP sessions are automatically reaped after the configured TTL.

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

For Streamable HTTP mode, build first and then point your MCP client at the
configured HTTP endpoint:

```bash
npm run build
MCP_TRANSPORT=streamable-http node dist/index.js
```

### Instructions

1. Set the environment variables as described in the [Environment Variables ](#environment-variables) step.
2. Run the command to start the MCP Inspector.
3. Open the MCP Inspector UI in your browser and click Connect to start the MCP server.
4. You can see all the available tools and test them individually.
