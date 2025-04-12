#!/usr/bin/env node

import { InfisicalSDK } from "@infisical/sdk";
import fs from "fs";
import path from "path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, "../package.json"), "utf-8")) as { version: string };

const getEnvironmentVariables = () => {
	const envSchema = z
		.object({
			INFISICAL_UNIVERSAL_AUTH_CLIENT_ID: z.string().trim().min(1),
			INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET: z.string().trim().min(1),
			INFISICAL_HOST_URL: z.string().default("https://app.infisical.com")
		})
		.parse(process.env);

	return envSchema;
};

const env = getEnvironmentVariables();
let isAuthenticated = false;
const infisicalSdk = new InfisicalSDK({
	siteUrl: env.INFISICAL_HOST_URL
});

const handleAuthentication = async () => {
	if (isAuthenticated) {
		return;
	}

	await infisicalSdk.auth().universalAuth.login({
		clientId: env.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID,
		clientSecret: env.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET
	});

	isAuthenticated = true;
};

const server = new Server(
	{
		name: "Infisical",
		version: packageJson.version
	},
	{
		capabilities: {
			tools: {}
		}
	}
);

enum AvailableTools {
	CreateSecret = "create-secret",
	DeleteSecret = "delete-secret",
	UpdateSecret = "update-secret",
	ListSecrets = "list-secrets",
	GetSecret = "get-secret",
	CreateProject = "create-project",
	CreateEnvironment = "create-environment",
	CreateFolder = "create-folder",
	InviteMembersToProject = "invite-members-to-project"
}

const createSecretSchema = {
	zod: z.object({
		projectId: z.string(),
		environmentSlug: z.string(),
		secretName: z.string(),
		secretValue: z.string().optional(),
		secretPath: z.string().default("/")
	}),
	capability: {
		name: AvailableTools.CreateSecret,
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
					description: "The path of the secret to create (Defaults to /)"
				}
			},
			required: ["projectId", "environmentSlug", "secretName"]
		}
	}
};

const deleteSecretSchema = {
	zod: z.object({
		projectId: z.string(),
		environmentSlug: z.string(),
		secretPath: z.string().default("/"),
		secretName: z.string()
	}),
	capability: {
		name: AvailableTools.DeleteSecret,
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
				secretPath: {
					type: "string",
					description: "The path of the secret to delete (Defaults to /)"
				},
				secretName: {
					type: "string",
					description: "The name of the secret to delete (required)"
				}
			},
			required: ["projectId", "environmentSlug", "secretName"]
		}
	}
};

const updateSecretSchema = {
	zod: z.object({
		projectId: z.string(),
		environmentSlug: z.string(),
		secretName: z.string(),
		newSecretName: z.string().optional(),
		secretValue: z.string().optional(),
		secretPath: z.string().default("/")
	}),
	capability: {
		name: AvailableTools.UpdateSecret,
		description: "Update a secret in Infisical",
		inputSchema: {
			type: "object",
			properties: {
				projectId: {
					type: "string",
					description: "The ID of the project to update the secret in (required)"
				},
				environmentSlug: {
					type: "string",
					description: "The slug of the environment to update the secret in (required)"
				},
				secretName: {
					type: "string",
					description: "The current name of the secret to update (required)"
				},
				newSecretName: {
					type: "string",
					description: "The new name of the secret to update (Optional)"
				},
				secretValue: {
					type: "string",
					description: "The new value of the secret to update (Optional)"
				},
				secretPath: {
					type: "string",
					description: "The path of the secret to update (Defaults to /)"
				}
			},
			required: ["projectId", "environmentSlug", "secretName"]
		}
	}
};

const listSecretsSchema = {
	zod: z.object({
		projectId: z.string(),
		environmentSlug: z.string(),
		secretPath: z.string().default("/"),
		expandSecretReferences: z.boolean().default(true),
		includeImports: z.boolean().default(true)
	}),
	capability: {
		name: AvailableTools.ListSecrets,
		description: "List all secrets in a given Infisical project and environment",
		inputSchema: {
			type: "object",
			properties: {
				projectId: {
					type: "string",
					description: "The ID of the project to list the secrets from (required)"
				},
				environmentSlug: {
					type: "string",
					description: "The slug of the environment to list the secrets from (required)"
				},
				secretPath: {
					type: "string",
					description: "The path of the secrets to list (Defaults to /)"
				},
				expandSecretReferences: {
					type: "boolean",
					description: "Whether to expand secret references (Defaults to true)"
				},
				includeImports: {
					type: "boolean",
					description: "Whether to include secret imports (Defaults to true)"
				}
			},
			required: ["projectId", "environmentSlug"]
		}
	}
};

const getSecretSchema = {
	zod: z.object({
		secretName: z.string(),
		projectId: z.string(),
		environmentSlug: z.string(),
		secretPath: z.string().default("/"),
		expandSecretReferences: z.boolean().default(true),
		includeImports: z.boolean().default(true)
	}),
	capability: {
		name: AvailableTools.GetSecret,
		description: "Get a secret in Infisical",
		inputSchema: {
			type: "object",
			properties: {
				secretName: {
					type: "string",
					description: "The name of the secret to get (required)"
				},
				projectId: {
					type: "string",
					description: "The ID of the project to get the secret from (required)"
				},
				environmentSlug: {
					type: "string",
					description: "The slug of the environment to get the secret from (required)"
				},
				secretPath: {
					type: "string",
					description: "The path of the secret to get (Defaults to /)"
				},
				expandSecretReferences: {
					type: "boolean",
					description: "Whether to expand secret references (Defaults to true)"
				},
				includeImports: {
					type: "boolean",
					description:
						"Whether to include secret imports. If the secret isn't found, it will try to find a secret in a secret import that matches the requested secret name (Defaults to true)"
				}
			},
			required: ["projectId", "environmentSlug", "secretName"]
		}
	}
};

const createProjectSchema = {
	zod: z.object({
		projectName: z.string(),
		type: z.enum(["secret-manager", "cert-manager", "kms", "ssh"]),
		description: z.string().optional(),
		slug: z.string().optional(),
		projectTemplate: z.string().optional(),
		kmsKeyId: z.string().optional()
	}),
	capability: {
		name: AvailableTools.CreateProject,
		description: "Create a new project in Infisical",
		inputSchema: {
			type: "object",
			properties: {
				projectName: {
					type: "string",
					description: "The name of the project to create (required)"
				},
				type: {
					type: "string",
					description:
						"The type of project to create (required). If not specified by the user, ask them to confirm the type they want to use."
				},
				description: {
					type: "string",
					description: "The description of the project to create"
				},
				slug: {
					type: "string",
					description: "The slug of the project to create"
				},
				projectTemplate: {
					type: "string",
					description: "The template of the project to create"
				},
				kmsKeyId: {
					type: "string",
					description: "The ID of the KMS key to use for the project. Defaults to Infisical's default KMS"
				}
			},
			required: ["projectName", "type"]
		}
	}
};

const createEnvironmentSchema = {
	zod: z.object({
		projectId: z.string(),
		name: z.string(),
		slug: z.string(),
		position: z.number().optional()
	}),
	capability: {
		name: AvailableTools.CreateEnvironment,
		description: "Create a new environment in Infisical",
		inputSchema: {
			type: "object",
			properties: {
				projectId: {
					type: "string",
					description: "The ID of the project to create the environment in (required)"
				},
				name: {
					type: "string",
					description: "The name of the environment to create (required)"
				},
				slug: {
					type: "string",
					description: "The slug of the environment to create (required)"
				},
				position: {
					type: "number",
					description: "The position of the environment to create"
				}
			},

			required: ["projectId", "name", "slug"]
		}
	}
};

const createFolderSchema = {
	zod: z.object({
		description: z.string().optional(),
		environment: z.string(),
		name: z.string(),
		path: z.string().default("/"),
		projectId: z.string()
	}),
	capability: {
		name: AvailableTools.CreateFolder,
		description: "Create a new folder in Infisical",
		inputSchema: {
			type: "object",
			properties: {
				description: {
					type: "string",
					description: "The description of the folder to create"
				},
				environment: {
					type: "string",
					description: "The environment to create the folder in (required)"
				},
				name: {
					type: "string",
					description: "The name of the folder to create (required)"
				},
				path: {
					type: "string",
					description: "The path to create the folder in (Defaults to /)"
				},
				projectId: {
					type: "string",
					description: "The project to create the folder in (required)"
				}
			},
			required: ["name", "projectId", "environment"]
		}
	}
};

const inviteMembersToProjectSchema = {
	zod: z.object({
		projectId: z.string(),
		emails: z.array(z.string()).optional(),
		usernames: z.array(z.string()).optional(),
		roleSlugs: z.array(z.string()).optional()
	}),
	capability: {
		name: AvailableTools.InviteMembersToProject,
		description: "Invite members to a project in Infisical",
		inputSchema: {
			type: "object",
			properties: {
				projectId: {
					type: "string",
					description: "The ID of the project to invite members to (required)"
				},
				emails: {
					type: "array",
					description: "The emails of the members to invite. Either usernames or emails must be provided."
				},
				usernames: {
					type: "array",
					description: "The usernames of the members to invite. Either usernames or emails must be provided."
				},
				roleSlugs: {
					type: "array",
					description:
						"The role slugs of the members to invite. If not provided, the default role 'member' will be used. Ask the user to confirm the role they want to use if not explicitly specified."
				}
			},
			required: ["projectId"]
		}
	}
};
server.setRequestHandler(ListToolsRequestSchema, async () => {
	return {
		tools: [
			createSecretSchema.capability,
			deleteSecretSchema.capability,
			updateSecretSchema.capability,
			listSecretsSchema.capability,
			getSecretSchema.capability,
			createProjectSchema.capability,
			createEnvironmentSchema.capability,
			createFolderSchema.capability,
			inviteMembersToProjectSchema.capability
		]
	};
});

server.setRequestHandler(CallToolRequestSchema, async req => {
	try {
		await handleAuthentication();

		const { name, arguments: args } = req.params;

		if (name === AvailableTools.CreateSecret) {
			const data = createSecretSchema.zod.parse(args);

			const { secret } = await infisicalSdk.secrets().createSecret(data.secretName, {
				environment: data.environmentSlug,
				projectId: data.projectId,
				secretPath: data.secretPath,
				secretValue: data.secretValue ?? ""
			});

			return {
				content: [
					{
						type: "text",
						text: `Secret created successfully: ${JSON.stringify(secret, null, 3)}`
					}
				]
			};
		}

		if (name === AvailableTools.DeleteSecret) {
			const data = deleteSecretSchema.zod.parse(args);

			const { secret } = await infisicalSdk.secrets().deleteSecret(data.secretName, {
				environment: data.environmentSlug,
				projectId: data.projectId,
				secretPath: data.secretPath
			});

			return {
				content: [
					{
						type: "text",
						text: `Secret deleted successfully: ${secret.secretKey}`
					}
				]
			};
		}

		if (name === AvailableTools.UpdateSecret) {
			const data = updateSecretSchema.zod.parse(args);

			const { secret } = await infisicalSdk.secrets().updateSecret(data.secretName, {
				environment: data.environmentSlug,
				projectId: data.projectId,
				secretPath: data.secretPath,
				secretValue: data.secretValue ?? ""
			});

			return {
				content: [
					{
						type: "text",
						text: `Secret updated successfully. Updated secret: ${JSON.stringify(secret, null, 3)}`
					}
				]
			};
		}

		if (name === AvailableTools.ListSecrets) {
			const data = listSecretsSchema.zod.parse(args);

			const secrets = await infisicalSdk.secrets().listSecrets({
				environment: data.environmentSlug,
				projectId: data.projectId,
				secretPath: data.secretPath,
				expandSecretReferences: data.expandSecretReferences,
				includeImports: data.includeImports
			});

			const response = {
				secrets: secrets.secrets.map(secret => ({
					secretKey: secret.secretKey,
					secretValue: secret.secretValue
				})),
				...(secrets.imports && {
					imports: secrets.imports?.map(imp => {
						const parsedImportSecrets = imp.secrets.map(secret => ({
							secretKey: secret.secretKey,
							secretValue: secret.secretValue
						}));

						return {
							...imp,
							secrets: parsedImportSecrets
						};
					})
				})
			};

			return {
				content: [
					{
						type: "text",
						text: `${JSON.stringify(response)}`
					}
				]
			};
		}

		if (name === AvailableTools.GetSecret) {
			const data = getSecretSchema.zod.parse(args);

			const secret = await infisicalSdk.secrets().getSecret({
				environment: data.environmentSlug,
				projectId: data.projectId,
				secretName: data.secretName,
				secretPath: data.secretPath,
				expandSecretReferences: data.expandSecretReferences,
				includeImports: data.includeImports
			});

			return {
				content: [
					{
						type: "text",
						text: `Secret retrieved successfully: ${JSON.stringify(secret, null, 3)}`
					}
				]
			};
		}

		if (name === AvailableTools.CreateProject) {
			const data = createProjectSchema.zod.parse(args);

			const project = await infisicalSdk.projects().create({
				projectName: data.projectName,
				projectDescription: data.description,
				kmsKeyId: data.kmsKeyId,
				slug: data.slug,
				template: data.projectTemplate,
				type: data.type
			});

			return {
				content: [
					{
						type: "text",
						text: `Project created successfully: ${JSON.stringify(project, null, 3)}`
					}
				]
			};
		}

		if (name === AvailableTools.CreateEnvironment) {
			const data = createEnvironmentSchema.zod.parse(args);

			const environment = await infisicalSdk.environments().create({
				projectId: data.projectId,
				name: data.name,
				slug: data.slug,
				position: data.position
			});

			return {
				content: [
					{
						type: "text",
						text: `Environment created successfully: ${JSON.stringify(environment, null, 3)}`
					}
				]
			};
		}

		if (name === AvailableTools.CreateFolder) {
			const data = createFolderSchema.zod.parse(args);

			const folder = await infisicalSdk.folders().create({
				description: data.description,
				environment: data.environment,
				name: data.name,
				path: data.path,
				projectId: data.projectId
			});

			return {
				content: [
					{
						type: "text",
						text: `Folder created successfully: ${JSON.stringify(folder, null, 3)}`
					}
				]
			};
		}

		if (name === AvailableTools.InviteMembersToProject) {
			const data = inviteMembersToProjectSchema.zod.parse(args);

			const projectMemberships = await infisicalSdk.projects().inviteMembers({
				projectId: data.projectId,
				emails: data.emails,
				usernames: data.usernames,
				roleSlugs: data.roleSlugs
			});

			return {
				content: [
					{
						type: "text",
						text: `Members successfully invited to project: ${JSON.stringify(projectMemberships, null, 3)}`
					}
				]
			};
		}

		throw new Error(`Unrecognized tool name: ${name}`);
	} catch (err) {
		if (err instanceof z.ZodError) {
			throw new Error(`Invalid arguments: ${err.errors.map(e => `${e.path.join(".")}: ${e.message}`).join(", ")}`);
		}
		throw err;
	}
});

(async () => {
	await server.connect(new StdioServerTransport());
	console.error("Infisical MCP Server running on stdio ✅");
})();
