#!/usr/bin/env node

import express from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import cors from 'cors';
import helmet from 'helmet';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { InfisicalSDK } from "@infisical/sdk";
import fs from "fs";
import path from "path";
import { z } from "zod";

const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, "../package.json"), "utf-8")) as { version: string };

// Environment validation
const getEnvironmentVariables = () => {
    const envSchema = z
        .object({
            INFISICAL_UNIVERSAL_AUTH_CLIENT_ID: z.string().trim().min(1),
            INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET: z.string().trim().min(1),
            INFISICAL_HOST_URL: z.string()
        })
        .parse(process.env);

    return envSchema;
};

const env = getEnvironmentVariables();

// Helper function to create a fresh authenticated SDK instance for each API call
const createAuthenticatedSdk = async () => {
    const sdk = new InfisicalSDK({
        siteUrl: env.INFISICAL_HOST_URL
    });

    try {
        const authResult = await sdk.auth().universalAuth.login({
            clientId: env.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID,
            clientSecret: env.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET
        });
        console.log('Authentication successful for fresh SDK instance');
        return sdk;
    } catch (error) {
        console.error('Authentication failed:', error);
        throw new Error(`Authentication failed: ${error.message}`);
    }
};


// Define schemas (same as index.ts)
const createSecretSchema = z.object({
    projectId: z.string(),
    environmentSlug: z.string(),
    secretName: z.string(),
    secretValue: z.string().optional(),
    secretPath: z.string().default("/")
});

const deleteSecretSchema = z.object({
    projectId: z.string(),
    environmentSlug: z.string(),
    secretName: z.string(),
    secretPath: z.string().default("/")
});

const updateSecretSchema = z.object({
    projectId: z.string(),
    environmentSlug: z.string(),
    secretName: z.string(),
    secretValue: z.string().optional(),
    secretPath: z.string().default("/")
});

const listSecretsSchema = z.object({
    projectId: z.string(),
    environmentSlug: z.string(),
    secretPath: z.string().default("/"),
    expandSecretReferences: z.boolean().optional(),
    includeImports: z.boolean().optional()
});

const getSecretSchema = z.object({
    projectId: z.string(),
    environmentSlug: z.string(),
    secretName: z.string(),
    secretPath: z.string().default("/"),
    expandSecretReferences: z.boolean().optional(),
    includeImports: z.boolean().optional()
});

const createProjectSchema = z.object({
    projectName: z.string(),
    workspaceSlug: z.string().optional(),
    organizationId: z.string().optional()
});

const listProjectsSchema = z.object({});

const createEnvironmentSchema = z.object({
    projectId: z.string(),
    environmentName: z.string(),
    environmentSlug: z.string().optional()
});

const createFolderSchema = z.object({
    projectId: z.string(),
    environmentSlug: z.string(),
    secretPath: z.string().default("/")
});

const inviteMembersToProjectSchema = z.object({
    projectId: z.string(),
    emails: z.array(z.string()),
    roles: z.array(z.string()).optional()
});

// Tool definitions with proper JSON Schema format for MCP
const tools = [
    {
        name: "create-secret",
        description: "Create a new secret in Infisical",
        inputSchema: {
            type: "object",
            properties: {
                projectId: {
                    type: "string",
                    description: "The ID of the project to create the secret in (required)"
                },
                environmentSlug: {
                    type: "string",
                    description: "The slug of the environment to create the secret in (required)"
                },
                secretName: {
                    type: "string",
                    description: "The name of the secret to create (required)"
                },
                secretValue: {
                    type: "string",
                    description: "The value of the secret to create"
                },
                secretPath: {
                    type: "string",
                    description: "The path of the secret to create (Defaults to /)",
                    default: "/"
                }
            },
            required: ["projectId", "environmentSlug", "secretName"]
        }
    },
    {
        name: "delete-secret",
        description: "Delete a secret in Infisical",
        inputSchema: {
            type: "object",
            properties: {
                projectId: {
                    type: "string",
                    description: "The ID of the project to delete the secret from (required)"
                },
                environmentSlug: {
                    type: "string",
                    description: "The slug of the environment to delete the secret from (required)"
                },
                secretName: {
                    type: "string",
                    description: "The name of the secret to delete (required)"
                },
                secretPath: {
                    type: "string",
                    description: "The path of the secret to delete (Defaults to /)",
                    default: "/"
                }
            },
            required: ["projectId", "environmentSlug", "secretName"]
        }
    },
    {
        name: "list-secrets",
        description: "List all secrets in an environment",
        inputSchema: {
            type: "object",
            properties: {
                projectId: {
                    type: "string",
                    description: "The ID of the project to list secrets from (required)"
                },
                environmentSlug: {
                    type: "string",
                    description: "The slug of the environment to list secrets from (required)"
                },
                secretPath: {
                    type: "string",
                    description: "The path to list secrets from (Defaults to /)",
                    default: "/"
                },
                expandSecretReferences: {
                    type: "boolean",
                    description: "Whether to expand secret references"
                },
                includeImports: {
                    type: "boolean",
                    description: "Whether to include imported secrets"
                }
            },
            required: ["projectId", "environmentSlug"]
        }
    },
    {
        name: "get-secret",
        description: "Get a specific secret",
        inputSchema: {
            type: "object",
            properties: {
                projectId: {
                    type: "string",
                    description: "The ID of the project to get the secret from (required)"
                },
                environmentSlug: {
                    type: "string",
                    description: "The slug of the environment to get the secret from (required)"
                },
                secretName: {
                    type: "string",
                    description: "The name of the secret to get (required)"
                },
                secretPath: {
                    type: "string",
                    description: "The path of the secret to get (Defaults to /)",
                    default: "/"
                },
                expandSecretReferences: {
                    type: "boolean",
                    description: "Whether to expand secret references"
                },
                includeImports: {
                    type: "boolean",
                    description: "Whether to include imported secrets"
                }
            },
            required: ["projectId", "environmentSlug", "secretName"]
        }
    },
    {
        name: "create-project",
        description: "Create a new project",
        inputSchema: {
            type: "object",
            properties: {
                projectName: {
                    type: "string",
                    description: "The name of the project to create (required)"
                },
                workspaceSlug: {
                    type: "string",
                    description: "The workspace slug for the project"
                },
                organizationId: {
                    type: "string",
                    description: "The organization ID for the project"
                }
            },
            required: ["projectName"]
        }
    },
    {
        name: "list-projects",
        description: "List all accessible projects",
        inputSchema: {
            type: "object",
            properties: {},
            required: []
        }
    },
    {
        name: "create-environment",
        description: "Create a new environment",
        inputSchema: {
            type: "object",
            properties: {
                projectId: {
                    type: "string",
                    description: "The ID of the project to create the environment in (required)"
                },
                environmentName: {
                    type: "string",
                    description: "The name of the environment to create (required)"
                },
                environmentSlug: {
                    type: "string",
                    description: "The slug of the environment to create"
                }
            },
            required: ["projectId", "environmentName"]
        }
    },
    {
        name: "create-folder",
        description: "Create a folder",
        inputSchema: {
            type: "object",
            properties: {
                projectId: {
                    type: "string",
                    description: "The ID of the project to create the folder in (required)"
                },
                environmentSlug: {
                    type: "string",
                    description: "The slug of the environment to create the folder in (required)"
                },
                secretPath: {
                    type: "string",
                    description: "The path where to create the folder (Defaults to /)",
                    default: "/"
                }
            },
            required: ["projectId", "environmentSlug"]
        }
    },
    {
        name: "invite-members-to-project",
        description: "Invite members to a project",
        inputSchema: {
            type: "object",
            properties: {
                projectId: {
                    type: "string",
                    description: "The ID of the project to invite members to (required)"
                },
                emails: {
                    type: "array",
                    items: {
                        type: "string"
                    },
                    description: "Array of email addresses to invite (required)"
                },
                roles: {
                    type: "array",
                    items: {
                        type: "string"
                    },
                    description: "Array of roles to assign to the invited members"
                }
            },
            required: ["projectId", "emails"]
        }
    }
];

// FlowMCP HTTP Server implementation
class FlowMCPHttpServer {
    private app: express.Application;
    private server: any;
    private wsServer: WebSocketServer;
    private port: number;
    private wsPort: number;

    constructor(port: number = 3000, wsPort: number = 3001) {
        this.port = port;
        this.wsPort = wsPort;
        this.app = express();
        this.setupMiddleware();
        this.setupRoutes();
    }

    private setupMiddleware() {
        this.app.use(helmet());
        this.app.use(cors({
            origin: '*',
            credentials: true
        }));
        this.app.use(express.json({ limit: '10mb' }));
    }

    private setupRoutes() {
        // Health check endpoint
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                service: 'Infisical FlowMCP HTTP Server',
                version: packageJson.version,
                port: this.port,
                wsPort: this.wsPort
            });
        });

        // Ready check endpoint
        this.app.get('/ready', (req, res) => {
            res.json({
                status: 'ready',
                tools: tools.length,
                authentication: isAuthenticated
            });
        });

        // MCP endpoint - support both GET (for discovery) and POST (for JSON-RPC)
        this.app.get('/mcp', (req, res) => {
            res.json({
                name: "Infisical MCP Server",
                version: "1.0.0",
                description: "Official Infisical MCP Server for secrets management",
                protocol: "MCP JSON-RPC over HTTP",
                endpoints: {
                    mcp: "/mcp",
                    health: "/health",
                    ready: "/ready"
                },
                capabilities: {
                    tools: {},
                    secrets: {}
                },
                tools: [
                    "create-secret", "delete-secret", "list-secrets",
                    "get-secret", "create-project", "list-projects",
                    "create-environment", "create-folder", "invite-members-to-project"
                ]
            });
        });

        this.app.post('/', this.handleJsonRpcRequest.bind(this));
        this.app.post('/rpc', this.handleJsonRpcRequest.bind(this));
        this.app.post('/mcp', this.handleJsonRpcRequest.bind(this));
    }

    private async handleJsonRpcRequest(req: express.Request, res: express.Response) {
        try {
            const { method, params, id } = req.body;

            // Cleaner logging - don't show undefined values for notifications
            const logData = { method };
            if (params !== undefined) logData.params = params;
            if (id !== undefined) logData.id = id;

            console.log(`[${new Date().toISOString()}] MCP Request:`, logData);

            switch (method) {
                case 'initialize':
                    const initResponse = {
                        jsonrpc: "2.0",
                        result: {
                            protocolVersion: "2024-11-05",
                            capabilities: {
                                tools: {},
                                logging: {},
                                streaming: true
                            },
                            serverInfo: {
                                name: "Infisical FlowMCP HTTP Server",
                                version: packageJson.version
                            }
                        },
                        id
                    };
                    return res.json(initResponse);

                case 'notifications/initialized':
                    // This is a notification from client indicating it's ready
                    // No response needed for notifications
                    return res.status(204).send();

                case 'tools/list':
                    const toolsResponse = {
                        jsonrpc: "2.0",
                        result: { tools },
                        id
                    };
                    return res.json(toolsResponse);

                case 'tools/call':
                    const result = await this.handleToolCall(params);
                    const callResponse = {
                        jsonrpc: "2.0",
                        result,
                        id
                    };
                    return res.json(callResponse);

                default:
                    const errorResponse = {
                        jsonrpc: "2.0",
                        error: {
                            code: -32601,
                            message: `Method not found: ${method}`
                        },
                        id
                    };
                    return res.status(404).json(errorResponse);

            }
        } catch (error) {
            console.error(`[${new Date().toISOString()}] MCP Error:`, error);
            const errorResponse = {
                jsonrpc: "2.0",
                error: {
                    code: -32603,
                    message: `Internal error: ${error.message}`
                },
                id: req.body?.id
            };
            return res.status(500).json(errorResponse);
        }
    }

    private async handleToolCall(params: any) {
        const { name, arguments: args } = params;

        switch (name) {
            case 'create-secret':
                const createData = createSecretSchema.parse(args);
                const sdk = await createAuthenticatedSdk();
                const { secret } = await sdk.secrets().createSecret(createData.secretName, {
                    environment: createData.environmentSlug,
                    projectId: createData.projectId,
                    secretPath: createData.secretPath,
                    secretValue: createData.secretValue ?? ""
                });
                return {
                    content: [
                        {
                            type: "text",
                            text: `Secret created successfully: ${JSON.stringify(secret, null, 3)}`
                        }
                    ]
                };

            case 'delete-secret':
                const deleteData = deleteSecretSchema.parse(args);
                const deleteSdk = await createAuthenticatedSdk();
                const deletedSecret = await deleteSdk.secrets().deleteSecret(deleteData.secretName, {
                    environment: deleteData.environmentSlug,
                    projectId: deleteData.projectId,
                    secretPath: deleteData.secretPath
                });
                return {
                    content: [
                        {
                            type: "text",
                            text: `Secret deleted successfully: ${deletedSecret.secretKey}`
                        }
                    ]
                };

            case 'update-secret':
                const updateData = updateSecretSchema.parse(args);
                const updateSdk = await createAuthenticatedSdk();
                const updatedSecret = await updateSdk.secrets().updateSecret(updateData.secretName, {
                    environment: updateData.environmentSlug,
                    projectId: updateData.projectId,
                    secretPath: updateData.secretPath,
                    secretValue: updateData.secretValue ?? ""
                });
                return {
                    content: [
                        {
                            type: "text",
                            text: `Secret updated successfully: ${JSON.stringify(updatedSecret, null, 3)}`
                        }
                    ]
                };

            case 'list-secrets':
                const listData = listSecretsSchema.parse(args);
                const listSdk = await createAuthenticatedSdk();
                const secrets = await listSdk.secrets().listSecrets({
                    environment: listData.environmentSlug,
                    projectId: listData.projectId,
                    secretPath: listData.secretPath,
                    expandSecretReferences: listData.expandSecretReferences,
                    includeImports: listData.includeImports
                });
                return {
                    content: [
                        {
                            type: "text",
                            text: `Secrets: ${JSON.stringify(secrets, null, 3)}`
                        }
                    ]
                };

            case 'get-secret':
                const getData = getSecretSchema.parse(args);
                const getSdk = await createAuthenticatedSdk();
                const allSecrets = await getSdk.secrets().listSecrets({
                    environment: getData.environmentSlug,
                    projectId: getData.projectId,
                    secretPath: getData.secretPath,
                    expandSecretReferences: getData.expandSecretReferences,
                    includeImports: getData.includeImports
                });
                const foundSecret = allSecrets.secrets.find(s => s.secretKey === getData.secretName);
                if (foundSecret) {
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Secret: ${JSON.stringify(foundSecret, null, 3)}`
                            }
                        ]
                    };
                } else {
                    return {
                        content: [
                            {
                                type: "text",
                                text: `Secret not found: ${getData.secretName}`
                            }
                        ]
                    };
                }

            case 'create-project':
                const projectData = createProjectSchema.parse(args);
                const projectSdk = await createAuthenticatedSdk();
                const project = await projectSdk.projects().create({
                    name: projectData.projectName,
                    workspaceSlug: projectData.workspaceSlug,
                    organizationId: projectData.organizationId
                });
                return {
                    content: [
                        {
                            type: "text",
                            text: `Project created successfully: ${JSON.stringify(project, null, 3)}`
                        }
                    ]
                };

            case 'list-projects':
                const listProjectsSdk = await createAuthenticatedSdk();
                const projects = await listProjectsSdk.projects().listProjects();
                return {
                    content: [
                        {
                            type: "text",
                            text: `Projects: ${JSON.stringify(projects, null, 3)}`
                        }
                    ]
                };

            case 'create-environment':
                const envData = createEnvironmentSchema.parse(args);
                const envSdk = await createAuthenticatedSdk();
                const environment = await envSdk.environments().create({
                    projectId: envData.projectId,
                    name: envData.environmentName,
                    slug: envData.environmentSlug
                });
                return {
                    content: [
                        {
                            type: "text",
                            text: `Environment created successfully: ${JSON.stringify(environment, null, 3)}`
                        }
                    ]
                };

            case 'create-folder':
                const folderData = createFolderSchema.parse(args);
                return {
                    content: [
                        {
                            type: "text",
                            text: `Folder creation request for path: ${folderData.secretPath}. Note: This functionality may need to be implemented based on your Infisical API version.`
                        }
                    ]
                };

            case 'invite-members-to-project':
                const inviteData = inviteMembersToProjectSchema.parse(args);
                return {
                    content: [
                        {
                            type: "text",
                            text: `Member invitation request for project: ${inviteData.projectId}, emails: ${inviteData.emails.join(', ')}. Note: This functionality may need to be implemented based on your Infisical API version.`
                        }
                    ]
                };

            default:
                throw new Error(`Unknown tool: ${name}`);
        }
    }

    async start() {
        // Start HTTP server
        this.server = this.app.listen(this.port, () => {
            console.log(`Starting Infisical FlowMCP HTTP Server on port ${this.port} ✅`);
            console.log(`Server supports MCP JSON-RPC over HTTP with proper protocol implementation`);
            console.log(`MCP endpoint available at http://localhost:${this.port}`);
            console.log(`WebSocket endpoint available at ws://localhost:${this.wsPort}`);
            console.log(`Health check available at http://localhost:${this.port}/health`);
            console.log(`Available tools: ${tools.map(t => t.name).join(', ')}`);
        });

        // Start WebSocket server
        this.wsServer = new WebSocketServer({ port: this.wsPort });

        this.wsServer.on('connection', (ws: WebSocket, req) => {
            console.log(`WebSocket client connected from ${req.socket.remoteAddress}`);

            ws.on('message', (message: string) => {
                try {
                    const data = JSON.parse(message);
                    console.log(`WebSocket message received:`, data);

                    // Handle WebSocket JSON-RPC requests
                    if (data.jsonrpc) {
                        this.handleJsonRpcRequest(data, ws);
                    }
                } catch (error) {
                    console.error('WebSocket message parsing error:', error);
                    ws.send(JSON.stringify({
                        jsonrpc: "2.0",
                        error: {
                            code: -32700,
                            message: "Parse error"
                        }
                    }));
                }
            });

            ws.on('close', () => {
                console.log('WebSocket client disconnected');
            });

            ws.on('error', (error) => {
                console.error('WebSocket error:', error);
            });
        });

        console.log(`WebSocket server started on port ${this.wsPort}`);
    }

    async stop() {
        return new Promise<void>((resolve) => {
            if (this.server) {
                this.server.close(() => {
                    console.log('HTTP server stopped');
                });
            }
            if (this.wsServer) {
                this.wsServer.close(() => {
                    console.log('WebSocket server stopped');
                });
            }
            resolve();
        });
    }
}

// Start the server
const PORT = process.env.PORT || 3333;
const WS_PORT = process.env.WS_PORT || 3334;

const server = new FlowMCPHttpServer(PORT, WS_PORT);
server.start().catch((error) => {
    console.error('Failed to start server:', error);
    process.exit(1);
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\nShutting down gracefully...');
    await server.stop();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('\nShutting down gracefully...');
    await server.stop();
    process.exit(0);
});