[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/infisical-infisical-mcp-server-badge.png)](https://mseep.ai/app/infisical-infisical-mcp-server)

# Infisical Model Context Protocol

The Infisical [Model Context Protocol](https://modelcontextprotocol.com/) server allows you to integrate with Infisical APIs through function calling. This protocol supports various tools to interact with Infisical.

## Setup

### Environment variables

In order to use the MCP server, you must first set the environment variables required for authentication.

- `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID`: The Machine Identity universal auth client ID that will be used for authentication
- `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET`: The Machine Identity universal auth client secret that will be used for authentication.
- `INFISICAL_HOST_URL`: **Optionally** set a custom host URL. This is useful if you're self-hosting Infisical or you're on dedicated infrastructure. Defaults to `https://app.infisical.com`

To run the Infisical MCP server using npx, use the following command:

```bash
npx -y @infisical/mcp
```

### Usage with Claude Desktop

Add the following to your `claude_desktop_config.json`. See [here](https://modelcontextprotocol.io/quickstart/user) for more details.

```json
{
  "mcpServers": {
    "infisical": {
      "command": "npx",
      "args": ["-y", "@infisical/mcp"],
      "env": {
        "INFISICAL_HOST_URL": "https://<custom-host-url>.com", // Optional
        "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": "<machine-identity-universal-auth-client-id>",
        "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "<machine-identity-universal-auth-client-secret"
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
