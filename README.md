# Infisical Model Context Protocol Server

The official Infisical [Model Context Protocol](https://modelcontextprotocol.com/) server provides seamless integration with Infisical's secrets management platform through function calling. This server supports both traditional stdio transport and modern HTTP streaming with WebSocket support for real-time applications.

## Features

- **Dual Transport Support**: Both stdio (traditional) and HTTP streaming modes
- **WebSocket Support**: Real-time bidirectional communication for streaming applications
- **Periodic Token Management**: Automatic token refresh for Infisical periodic auth tokens
- **n8n Compatible**: Full compatibility with n8n workflow automation
- **All Infisical Tools**: Complete access to secrets, projects, environments, and more
- **Health Monitoring**: Built-in health check endpoints
- **CORS Support**: Web application ready

## Setup

### Environment Variables

Required for authentication with Infisical:

- `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID`: Machine Identity universal auth client ID
- `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET`: Machine Identity universal auth client secret
- `INFISICAL_HOST_URL`: Infisical host URL (e.g., `https://app.infisical.com` for cloud)

## Running the Server

### Stdio Mode (Traditional)

For standard MCP client integrations:

```bash
npx -y @infisical/mcp
```

### HTTP Mode (FlowMCP)

For web applications, streaming, and n8n integration:

```bash
# Build the server
npm run build

# Start HTTP server
npm run start:http
```

The FlowMCP HTTP server provides:
- **Main Endpoint**: `http://localhost:3333/mcp` (JSON-RPC over HTTP)
- **WebSocket**: `ws://localhost:3334` (real-time streaming)
- **Health Check**: `http://localhost:3333/health`
- **Discovery**: `http://localhost:3333/mcp` (GET for server info)

### Docker Deployment

#### Docker Compose

```bash
# Set environment variables
export INFISICAL_UNIVERSAL_AUTH_CLIENT_ID="your-client-id"
export INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET="your-client-secret"
export INFISICAL_HOST_URL="https://app.infisical.com"

# Start HTTP server (recommended)
docker-compose up infisical-mcp-http

# Or start stdio server
docker-compose up infisical-mcp-stdio
```

#### Direct Docker

```bash
# Build image
docker build -t infisical-mcp .

# Run HTTP server
docker run -p 3333:3333 \
  -e INFISICAL_UNIVERSAL_AUTH_CLIENT_ID="your-client-id" \
  -e INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET="your-client-secret" \
  -e INFISICAL_HOST_URL="https://app.infisical.com" \
  infisical-mcp

# Run stdio server
docker run \
  -e INFISICAL_UNIVERSAL_AUTH_CLIENT_ID="your-client-id" \
  -e INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET="your-client-secret" \
  -e INFISICAL_HOST_URL="https://app.infisical.com" \
  --entrypoint node infisical-mcp dist/index.js
```

## Integration Examples

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "infisical": {
      "command": "npx",
      "args": ["-y", "@infisical/mcp"],
      "env": {
        "INFISICAL_HOST_URL": "https://app.infisical.com",
        "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": "<machine-identity-client-id>",
        "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "<machine-identity-client-secret>"
      }
    }
  }
}
```

### n8n Integration

For n8n workflow automation, use the HTTP endpoint:

**Server URL**: `http://localhost:3333` (or your deployed URL)
**Transport**: HTTP JSON-RPC
**Endpoint**: `/mcp`

The FlowMCP server is fully compatible with n8n's MCP client tool and supports:
- Automatic session initialization
- Tool discovery and execution
- Periodic token refresh for long-running workflows

### HTTP Client Example

```bash
# Discover server information
curl http://localhost:3333/mcp

# List available tools
curl -X POST http://localhost:3333/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
  }'

# Initialize session
curl -X POST http://localhost:3333/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {"tools": {}},
      "clientInfo": {"name": "test-client", "version": "1.0.0"}
    }
  }'
```

## Available Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `create-secret` | Create a new secret | `projectId`, `environmentSlug`, `secretName`, `secretValue`, `secretPath` |
| `delete-secret` | Delete a secret | `projectId`, `environmentSlug`, `secretName`, `secretPath` |
| `update-secret` | Update a secret | `projectId`, `environmentSlug`, `secretName`, `secretValue`, `secretPath` |
| `list-secrets` | List all secrets | `projectId`, `environmentSlug`, `secretPath`, `expandSecretReferences`, `includeImports` |
| `get-secret` | Get a specific secret | `projectId`, `environmentSlug`, `secretName`, `secretPath`, `expandSecretReferences`, `includeImports` |
| `create-project` | Create a new project | `projectName`, `workspaceSlug`, `organizationId` |
| `list-projects` | List all projects | None |
| `create-environment` | Create a new environment | `projectId`, `environmentName`, `environmentSlug` |
| `create-folder` | Create a new folder* | `projectId`, `environmentSlug`, `secretPath` |
| `invite-members-to-project` | Invite members to project* | `projectId`, `emails` |

*Note: Some tools may require additional implementation based on your Infisical API version.*

## Architecture

### FlowMCP HTTP Server

The HTTP server uses a custom FlowMCP implementation with:

- **Express.js**: Robust HTTP server with comprehensive middleware
- **WebSocket Server**: Real-time bidirectional communication on port 3334
- **JSON-RPC 2.0**: Standard protocol compliance
- **Per-Request Authentication**: Fresh tokens for each API call (ideal for periodic tokens)
- **Session Management**: Proper MCP session lifecycle
- **Error Handling**: Comprehensive error responses and logging

### Token Refresh Strategy

For Infisical periodic tokens (expiring after 3600 seconds), the server implements per-request authentication:

1. **Fresh SDK Instance**: Each tool call creates a new SDK instance
2. **New Authentication**: Every API call obtains a fresh access token
3. **No Expiration Issues**: Tokens never expire since they're refreshed per call
4. **Backward Compatible**: Still works with regular tokens

This approach ensures reliable operation for long-running workflows and automation tools.

## Development

### Building

```bash
npm run build
```

### Testing

```bash
# Test stdio server with MCP Inspector
npx @modelcontextprotocol/inspector node dist/index.js

# Test HTTP server
npm run start:http

# Test HTTP endpoints
curl http://localhost:3333/health
curl http://localhost:3333/mcp
```

### Project Structure

```
src/
├── index.ts              # Stdio MCP server (traditional)
├── flowmcp-server.ts     # HTTP/Streaming MCP server (FlowMCP)
└── schemas/              # Tool schemas and validation
```

## Security Considerations

- **Environment Variables**: Never commit secrets to version control
- **HTTPS**: Use HTTPS in production for HTTP mode
- **Network Access**: Restrict network access to the MCP server
- **Token Rotation**: Periodic tokens automatically refresh per request
- **Audit Logs**: Monitor server logs for authentication and tool usage

## Troubleshooting

### Common Issues

1. **Authentication Errors**: Verify environment variables and token validity
2. **Port Conflicts**: Ensure ports 3333 (HTTP) and 3334 (WebSocket) are available
3. **Network Issues**: Check firewall and network connectivity
4. **Token Expiration**: Use FlowMCP mode for automatic token refresh

### Debug Mode

Enable debug logging by setting:

```bash
export DEBUG=infisical-mcp:*
npm run start:http
```

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [Infisical Docs](https://infisical.com/docs/)
- **Issues**: [GitHub Issues](https://github.com/Infisical/infisical-mcp-server/issues)
- **Community**: [Infisical Discord](https://discord.gg/9CrVTJX)