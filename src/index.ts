#!/usr/bin/env node

import {
  InfisicalSDK,
  type GetSecretResponse,
  type ListSecretsResponse,
  type Secret,
} from "@infisical/sdk";
import fs from "fs";
import axios from "axios";
import path from "path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  type CallToolRequest,
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

enum InfisicalAuthMethod {
  UniversalAuth = "universal-auth",
  TokenAuth = "access-token",
}

enum AvailableTools {
  CreateSecret = "create-secret",
  DeleteSecret = "delete-secret",
  UpdateSecret = "update-secret",
  ListSecrets = "list-secrets",
  GetSecret = "get-secret",
  CreateProject = "create-project",
  CreateEnvironment = "create-environment",
  CreateFolder = "create-folder",
  InviteMembersToProject = "invite-members-to-project",
  ListProjects = "list-projects",
}

const ALL_TOOLS = Object.values(AvailableTools);

// the INFISICAL_ENABLED_TOOLS value that exposes every tool
const ALL_TOOLS_KEYWORD = "all";

// must match ProjectType in the API
const PROJECT_TYPES = [
  "secret-manager",
  "cert-manager",
  "kms",
  "secret-scanning",
  "pam",
] as const;

const LIST_PROJECT_TYPES = [...PROJECT_TYPES, "all"] as const;

const MASKED_VALUE = "<masked>";

// a blank value means unset; env templates often declare every key empty
const stringBoolean = (defaultValue: boolean) =>
  z
    .string()
    .trim()
    .toLowerCase()
    .optional()
    .transform((val, ctx) => {
      if (!val) return defaultValue;
      if (val === "true") return true;
      if (val === "false") return false;

      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `must be "true" or "false", received "${val}"`,
      });
      return z.NEVER;
    });

const packageJson = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../package.json"), "utf-8"),
) as { version: string };

export const getEnvironmentVariables = (
  source: NodeJS.ProcessEnv = process.env,
) => {
  const envSchema = z
    .object({
      INFISICAL_AUTH_METHOD: z
        .nativeEnum(InfisicalAuthMethod)
        .default(InfisicalAuthMethod.UniversalAuth),
      INFISICAL_TOKEN: z.string().trim().min(1).optional(),
      INFISICAL_UNIVERSAL_AUTH_CLIENT_ID: z.string().trim().min(1).optional(),
      INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET: z
        .string()
        .trim()
        .min(1)
        .optional(),
      INFISICAL_HOST_URL: z
        .string()
        .url()
        .default("https://app.infisical.com"),
      INFISICAL_ENABLED_TOOLS: z
        .string()
        .trim()
        .optional()
        .transform((val, ctx) => {
          // an empty value is an error, not "expose everything". the list is
          // copied so a caller changing its env cannot change it for every server
          if (val === undefined) return [...ALL_TOOLS];

          const requested = val
            .split(",")
            .map((name) => name.trim())
            .filter(Boolean);

          if (requested.includes(ALL_TOOLS_KEYWORD)) {
            if (requested.length > 1) {
              ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: `INFISICAL_ENABLED_TOOLS can be "${ALL_TOOLS_KEYWORD}" or a list of tools, not both.`,
              });
              return z.NEVER;
            }

            return [...ALL_TOOLS];
          }

          const unknown = requested.filter(
            (name) => !ALL_TOOLS.includes(name as AvailableTools),
          );
          if (unknown.length) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: `INFISICAL_ENABLED_TOOLS contains unknown tool(s): ${unknown.join(", ")}. Valid tools are: ${ALL_TOOLS.join(", ")}, or "${ALL_TOOLS_KEYWORD}" on its own.`,
            });
            return z.NEVER;
          }
          if (!requested.length) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: `INFISICAL_ENABLED_TOOLS was set but lists no tools. Omit it, or set it to "${ALL_TOOLS_KEYWORD}", to expose every tool.`,
            });
            return z.NEVER;
          }

          return requested as AvailableTools[];
        }),
      INFISICAL_MASK_SECRET_VALUES: stringBoolean(false),
      INFISICAL_AUDIT_LOG: stringBoolean(true),
    })
    // validate the env vars on startup to avoid runtime errors
    .superRefine((data, ctx) => {
      const missingClientIdOrClientSecret =
        !data.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID ||
        !data.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET;

      const missingToken = !data.INFISICAL_TOKEN;

      switch (data.INFISICAL_AUTH_METHOD) {
        case InfisicalAuthMethod.UniversalAuth:
          if (missingClientIdOrClientSecret) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message:
                "Authentication method is set to universal auth, but INFISICAL_UNIVERSAL_AUTH_CLIENT_ID or INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET is not set",
            });
          }
          break;
        case InfisicalAuthMethod.TokenAuth:
          if (missingToken) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message:
                "Authentication method is set to token auth, but INFISICAL_TOKEN is not set",
            });
          }
          break;
        default:
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `Unsupported authentication method: ${data.INFISICAL_AUTH_METHOD}`,
          });
          break;
      }
    })
    .parse(source);

  return envSchema;
};

type Env = ReturnType<typeof getEnvironmentVariables>;

// log in again this long before the access token expires, or halfway through
// its lifetime if that comes first, so a short TTL is not a login per call
const TOKEN_RENEWAL_MARGIN_MS = 60 * 1000;

// work out when to log in again from the access token's iat and exp, so a
// universal auth session outlives a short TTL. the lifetime is measured from
// iat, so a local clock that disagrees with Infisical's does not matter.
// nothing is trusted from the token; Infisical verifies it on every call
const getRenewalTime = (token: string | null, requestedAt: number) => {
  try {
    const { exp, iat } = JSON.parse(
      Buffer.from(token!.split(".")[1], "base64url").toString("utf-8"),
    );
    if (typeof exp !== "number") return undefined;

    const lifetimeMs =
      typeof iat === "number" ? (exp - iat) * 1000 : exp * 1000 - requestedAt;
    const marginMs = Math.min(TOKEN_RENEWAL_MARGIN_MS, lifetimeMs / 2);

    return requestedAt + lifetimeMs - marginMs;
  } catch {
    // a token without a readable exp is treated as never expiring
    return undefined;
  }
};

// match the SDK's own client: a 10 second timeout, and up to four retries with
// exponential backoff when rate limited or when no response comes back
const API_TIMEOUT_MS = 10 * 1000;
const API_MAX_RETRIES = 4;
const API_RETRY_DELAY_MS = 1000;

// a write to an environment with a change policy returns a change request
// instead of the secret, and only takes effect once it is approved
type ChangeRequest = { id: string; slug: string; status: string };

type SecretWriteResponse = { secret: Secret } | { approval: ChangeRequest };

const pendingApproval = ({ id, slug, status }: ChangeRequest) => ({
  content: [
    {
      type: "text",
      text: `The change was not applied yet. This environment requires approval for secret changes, so it is waiting in a change request: ${JSON.stringify({ id, slug, status }, null, 3)}`,
    },
  ],
});

// lets the audit log tell a disabled tool apart from other failures
class ToolNotEnabledError extends McpError {
  constructor(message: string) {
    super(ErrorCode.InvalidParams, message);
  }
}

class ApiRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly apiMessage?: string,
  ) {
    super(message);
  }
}

// Infisical, like Fastify's own default, answers a route it does not have
// with "Route GET:/api/v4/secrets?... not found"
const isRouteNotFound = (err: unknown) =>
  err instanceof ApiRequestError &&
  err.status === 404 &&
  /^Route \S+ not found/.test(err.apiMessage ?? "");

// the v3 secret routes take the same fields as v4, with the project renamed
const V3_FIELD_NAMES: Record<string, string> = {
  projectId: "workspaceId",
};

const toV3Fields = <V>(fields: Record<string, V>) => {
  const renamed: Record<string, V> = {};

  for (const key of Object.keys(fields)) {
    renamed[V3_FIELD_NAMES[key] ?? key] = fields[key];
  }

  return renamed;
};

// the SDK's errors only carry the status in their message: [StatusCode=401]
// when the response had a message, axios's own wording when it did not
const isUnauthorized = (err: unknown) =>
  err instanceof ApiRequestError
    ? err.status === 401
    : err instanceof Error &&
      /\[StatusCode=401\]|status code 401\b/.test(err.message);

type LogEntry = Record<string, unknown>;

// stdout carries the MCP protocol, so logs go to stderr, one JSON object per line
const writeLog = (entry: LogEntry) => {
  process.stderr.write(
    `${JSON.stringify({ time: new Date().toISOString(), ...entry })}\n`,
  );
};

// the tool arguments an audit entry records. secret values are never among
// them, and anything not listed here is left out
const AUDITED_ARGUMENTS = [
  "projectId",
  "projectName",
  "slug",
  "type",
  "environmentSlug",
  "environment",
  "secretPath",
  "path",
  "secretName",
  "newSecretName",
  "name",
  "emails",
  "usernames",
  "roleSlugs",
];

const auditedArguments = (args: Record<string, unknown> | undefined) => {
  const audited: Record<string, unknown> = {};

  for (const key of AUDITED_ARGUMENTS) {
    const value = args?.[key];
    const isLoggable =
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean" ||
      (Array.isArray(value) && value.every((item) => typeof item === "string"));

    if (isLoggable) {
      audited[key] = value;
    }
  }

  return audited;
};

const createSecretSchema = {
  zod: z.object({
    projectId: z.string(),
    environmentSlug: z.string(),
    secretName: z.string(),
    secretValue: z.string().optional(),
    secretPath: z.string().default("/"),
  }),
  capability: {
    name: AvailableTools.CreateSecret,
    annotations: {
      title: "Create secret",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
    description: "Create a new secret in Infisical",
    inputSchema: {
      type: "object",
      properties: {
        projectId: {
          type: "string",
          description:
            "The ID of the project to create the secret in (required)",
        },
        environmentSlug: {
          type: "string",
          description:
            "The slug of the environment to create the secret in (required)",
        },
        secretName: {
          type: "string",
          description: "The name of the secret to create (required)",
        },
        secretValue: {
          type: "string",
          description: "The value of the secret to create",
        },
        secretPath: {
          type: "string",
          description: "The path of the secret to create (Defaults to /)",
        },
      },
      required: ["projectId", "environmentSlug", "secretName"],
    },
  },
};

const deleteSecretSchema = {
  zod: z.object({
    projectId: z.string(),
    environmentSlug: z.string(),
    secretPath: z.string().default("/"),
    secretName: z.string(),
  }),
  capability: {
    name: AvailableTools.DeleteSecret,
    annotations: {
      title: "Delete secret",
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
    },
    description: "Delete a secret in Infisical",
    inputSchema: {
      type: "object",
      properties: {
        projectId: {
          type: "string",
          description:
            "The ID of the project to delete the secret from (required)",
        },
        environmentSlug: {
          type: "string",
          description:
            "The slug of the environment to delete the secret from (required)",
        },
        secretPath: {
          type: "string",
          description: "The path of the secret to delete (Defaults to /)",
        },
        secretName: {
          type: "string",
          description: "The name of the secret to delete (required)",
        },
      },
      required: ["projectId", "environmentSlug", "secretName"],
    },
  },
};

const updateSecretSchema = {
  zod: z.object({
    projectId: z.string(),
    environmentSlug: z.string(),
    secretName: z.string(),
    newSecretName: z.string().optional(),
    secretValue: z.string().optional(),
    secretPath: z.string().default("/"),
  }),
  capability: {
    name: AvailableTools.UpdateSecret,
    annotations: {
      title: "Update secret",
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
    },
    description: "Update a secret in Infisical",
    inputSchema: {
      type: "object",
      properties: {
        projectId: {
          type: "string",
          description:
            "The ID of the project to update the secret in (required)",
        },
        environmentSlug: {
          type: "string",
          description:
            "The slug of the environment to update the secret in (required)",
        },
        secretName: {
          type: "string",
          description: "The current name of the secret to update (required)",
        },
        newSecretName: {
          type: "string",
          description: "The new name of the secret to update (Optional)",
        },
        secretValue: {
          type: "string",
          description: "The new value of the secret to update (Optional)",
        },
        secretPath: {
          type: "string",
          description: "The path of the secret to update (Defaults to /)",
        },
      },
      required: ["projectId", "environmentSlug", "secretName"],
    },
  },
};

const listSecretsSchema = {
  zod: z.object({
    projectId: z.string(),
    environmentSlug: z.string(),
    secretPath: z.string().default("/"),
    expandSecretReferences: z.boolean().default(true),
    includeImports: z.boolean().default(true),
  }),
  capability: {
    name: AvailableTools.ListSecrets,
    annotations: {
      title: "List secrets",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
    },
    description:
      "List all secrets in a given Infisical project and environment",
    inputSchema: {
      type: "object",
      properties: {
        projectId: {
          type: "string",
          description:
            "The ID of the project to list the secrets from (required)",
        },
        environmentSlug: {
          type: "string",
          description:
            "The slug of the environment to list the secrets from (required)",
        },
        secretPath: {
          type: "string",
          description: "The path of the secrets to list (Defaults to /)",
        },
        expandSecretReferences: {
          type: "boolean",
          description: "Whether to expand secret references (Defaults to true)",
        },
        includeImports: {
          type: "boolean",
          description: "Whether to include secret imports (Defaults to true)",
        },
      },
      required: ["projectId", "environmentSlug"],
    },
  },
};

const getSecretSchema = {
  zod: z.object({
    secretName: z.string(),
    projectId: z.string(),
    environmentSlug: z.string(),
    secretPath: z.string().default("/"),
    expandSecretReferences: z.boolean().default(true),
    includeImports: z.boolean().default(true),
  }),
  capability: {
    name: AvailableTools.GetSecret,
    annotations: {
      title: "Get secret",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
    },
    description: "Get a secret in Infisical",
    inputSchema: {
      type: "object",
      properties: {
        secretName: {
          type: "string",
          description: "The name of the secret to get (required)",
        },
        projectId: {
          type: "string",
          description:
            "The ID of the project to get the secret from (required)",
        },
        environmentSlug: {
          type: "string",
          description:
            "The slug of the environment to get the secret from (required)",
        },
        secretPath: {
          type: "string",
          description: "The path of the secret to get (Defaults to /)",
        },
        expandSecretReferences: {
          type: "boolean",
          description: "Whether to expand secret references (Defaults to true)",
        },
        includeImports: {
          type: "boolean",
          description:
            "Whether to include secret imports. If the secret isn't found, it will try to find a secret in a secret import that matches the requested secret name (Defaults to true)",
        },
      },
      required: ["projectId", "environmentSlug", "secretName"],
    },
  },
};

const createProjectSchema = {
  zod: z.object({
    projectName: z.string(),
    type: z.enum(PROJECT_TYPES),
    description: z.string().optional(),
    slug: z.string().optional(),
    projectTemplate: z.string().optional(),
    kmsKeyId: z.string().optional(),
  }),
  capability: {
    name: AvailableTools.CreateProject,
    annotations: {
      title: "Create project",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
    description: "Create a new project in Infisical",
    inputSchema: {
      type: "object",
      properties: {
        projectName: {
          type: "string",
          description: "The name of the project to create (required)",
        },
        type: {
          type: "string",
          enum: [...PROJECT_TYPES],
          description:
            "The type of project to create (required). If not specified by the user, ask them to confirm the type they want to use.",
        },
        description: {
          type: "string",
          description: "The description of the project to create",
        },
        slug: {
          type: "string",
          description: "The slug of the project to create",
        },
        projectTemplate: {
          type: "string",
          description: "The template of the project to create",
        },
        kmsKeyId: {
          type: "string",
          description:
            "The ID of the KMS key to use for the project. Defaults to Infisical's default KMS",
        },
      },
      required: ["projectName", "type"],
    },
  },
};

const createEnvironmentSchema = {
  zod: z.object({
    projectId: z.string(),
    name: z.string(),
    slug: z.string(),
    position: z.number().optional(),
  }),
  capability: {
    name: AvailableTools.CreateEnvironment,
    annotations: {
      title: "Create environment",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
    description: "Create a new environment in Infisical",
    inputSchema: {
      type: "object",
      properties: {
        projectId: {
          type: "string",
          description:
            "The ID of the project to create the environment in (required)",
        },
        name: {
          type: "string",
          description: "The name of the environment to create (required)",
        },
        slug: {
          type: "string",
          description: "The slug of the environment to create (required)",
        },
        position: {
          type: "number",
          description: "The position of the environment to create",
        },
      },

      required: ["projectId", "name", "slug"],
    },
  },
};

const createFolderSchema = {
  zod: z.object({
    description: z.string().optional(),
    environment: z.string(),
    name: z.string(),
    path: z.string().default("/"),
    projectId: z.string(),
  }),
  capability: {
    name: AvailableTools.CreateFolder,
    annotations: {
      title: "Create folder",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
    description: "Create a new folder in Infisical",
    inputSchema: {
      type: "object",
      properties: {
        description: {
          type: "string",
          description: "The description of the folder to create",
        },
        environment: {
          type: "string",
          description: "The environment to create the folder in (required)",
        },
        name: {
          type: "string",
          description: "The name of the folder to create (required)",
        },
        path: {
          type: "string",
          description: "The path to create the folder in (Defaults to /)",
        },
        projectId: {
          type: "string",
          description: "The project to create the folder in (required)",
        },
      },
      required: ["name", "projectId", "environment"],
    },
  },
};

const listProjectsSchema = {
  zod: z.object({
    type: z.enum(LIST_PROJECT_TYPES).default("all"),
  }),
  capability: {
    name: AvailableTools.ListProjects,
    annotations: {
      title: "List projects",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
    },
    description:
      "List all projects in Infisical that the machine identity has access to. If the user asks to list all projects, use the `all` type parameter.",
    inputSchema: {
      type: "object",
      properties: {
        type: {
          type: "string",
          enum: [...LIST_PROJECT_TYPES],
          description:
            "The type of projects to retrieve. If not specified, `all` projects will be retrieved.",
        },
      },
    },
  },
};

const inviteMembersToProjectSchema = {
  zod: z.object({
    projectId: z.string(),
    emails: z.array(z.string()).optional(),
    usernames: z.array(z.string()).optional(),
    roleSlugs: z.array(z.string()).optional(),
  }),
  capability: {
    name: AvailableTools.InviteMembersToProject,
    annotations: {
      title: "Invite members to project",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
    description: "Invite members to a project in Infisical",
    inputSchema: {
      type: "object",
      properties: {
        projectId: {
          type: "string",
          description: "The ID of the project to invite members to (required)",
        },
        emails: {
          type: "array",
          description:
            "The emails of the members to invite. Either usernames or emails must be provided.",
        },
        usernames: {
          type: "array",
          description:
            "The usernames of the members to invite. Either usernames or emails must be provided.",
        },
        roleSlugs: {
          type: "array",
          description:
            "The role slugs of the members to invite. If not provided, the default role 'member' will be used. Ask the user to confirm the role they want to use if not explicitly specified.",
        },
      },
      required: ["projectId"],
    },
  },
};
const allCapabilities = [
  createSecretSchema.capability,
  deleteSecretSchema.capability,
  updateSecretSchema.capability,
  listSecretsSchema.capability,
  getSecretSchema.capability,
  createProjectSchema.capability,
  createEnvironmentSchema.capability,
  createFolderSchema.capability,
  inviteMembersToProjectSchema.capability,
  listProjectsSchema.capability,
];

type ServerOptions = {
  log?: (entry: LogEntry) => void;
  // the tests shorten these so timeouts and retries run quickly
  requestTimeoutMs?: number;
  retryDelayMs?: number;
};

export const createServer = (
  env: Env,
  {
    log = writeLog,
    requestTimeoutMs = API_TIMEOUT_MS,
    retryDelayMs = API_RETRY_DELAY_MS,
  }: ServerOptions = {},
) => {
  let isAuthenticated = false;
  let renewLoginAt: number | undefined;
  let pendingLogin: Promise<void> | undefined;
  let loginAttempts = 0;
  const infisicalSdk = new InfisicalSDK({
    siteUrl: env.INFISICAL_HOST_URL,
  });

  const logIn = async () => {
    loginAttempts++;

    switch (env.INFISICAL_AUTH_METHOD) {
      case InfisicalAuthMethod.UniversalAuth: {
        const requestedAt = Date.now();
        await infisicalSdk.auth().universalAuth.login({
          clientId: env.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID!,
          clientSecret: env.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET!,
        });
        renewLoginAt = getRenewalTime(
          infisicalSdk.auth().getAccessToken(),
          requestedAt,
        );
        break;
      }
      case InfisicalAuthMethod.TokenAuth:
        infisicalSdk.auth().accessToken(env.INFISICAL_TOKEN!);
        break;
      default:
        throw new Error(
          `Unsupported authentication method: ${env.INFISICAL_AUTH_METHOD}`,
        );
    }

    isAuthenticated = true;
  };

  const handleAuthentication = async () => {
    const isRenewalDue =
      renewLoginAt !== undefined && Date.now() >= renewLoginAt;

    if (isAuthenticated && !isRenewalDue) {
      return;
    }

    // calls that arrive while a login is under way wait for it, rather than
    // each spending a login of their own
    if (!pendingLogin) {
      pendingLogin = (async () => {
        try {
          await logIn();
        } finally {
          pendingLogin = undefined;
        }
      })();
    }

    await pendingLogin;
  };

  const maskSecret = <T extends { secretValue?: string }>(secret: T): T => {
    if (!env.INFISICAL_MASK_SECRET_VALUES || secret.secretValue === undefined) {
      return secret;
    }

    return { ...secret, secretValue: MASKED_VALUE };
  };

  const apiUrl = (route: string) => {
    let hostUrl = env.INFISICAL_HOST_URL;
    if (!hostUrl.endsWith("/api")) {
      if (hostUrl.endsWith("/")) {
        hostUrl = hostUrl.slice(0, -1);
      }

      hostUrl += "/api";
    }

    return `${hostUrl}${route}`;
  };

  const apiRequest = async <T>(
    method: "GET" | "POST" | "PATCH" | "DELETE",
    route: string,
    {
      params,
      data,
    }: {
      params?: Record<string, string | undefined>;
      data?: Record<string, unknown>;
    },
    signal: AbortSignal,
  ) => {
    for (let attempt = 0; ; attempt++) {
      try {
        const res = await axios.request<T>({
          method,
          url: apiUrl(route),
          params,
          data,
          signal,
          timeout: requestTimeoutMs,
          headers: {
            Authorization: `Bearer ${infisicalSdk.auth().getAccessToken()}`,
          },
        });

        return res.data;
      } catch (err) {
        if (!axios.isAxiosError(err)) throw err;

        // a cancelled call also arrives without a response, but is not retried
        const isRetryable =
          !axios.isCancel(err) &&
          (err.response === undefined || err.response.status === 429);

        if (isRetryable && attempt < API_MAX_RETRIES) {
          const delay = retryDelayMs * 2 ** attempt;
          const jitter = (Math.random() * 2 - 1) * delay * 0.2;
          await new Promise((resolve) => setTimeout(resolve, delay + jitter));
          continue;
        }

        // rethrow a plain error, since an axios error carries the request
        // config and the bearer token with it
        if (!err.response) throw new Error(err.message);

        const apiMessage = (err.response.data as { message?: string })
          ?.message;
        throw new ApiRequestError(
          `Infisical API returned ${err.response.status}: ${apiMessage ?? err.message}`,
          err.response.status,
          apiMessage,
        );
      }
    }
  };

  // a log entry that cannot be written must not change how a call turns out
  const safeLog = (entry: LogEntry) => {
    try {
      log(entry);
    } catch {
      // there is nowhere left to report it
    }
  };

  // the secret tools call the v4 secrets API directly. the SDK targets the
  // deprecated v3 routes, and sends their imports flag under a name they
  // ignore, so imports never came back. v4 is also the API that Infisical's
  // own end-to-end tests cover.
  //
  // self-hosted versions before v0.150.0 have no v4 secrets API. the first
  // time Infisical says the v4 route does not exist, switch to the v3 routes
  // for the rest of the session
  let useV3SecretRoutes = false;

  const secretRequest = async <T>(
    method: "GET" | "POST" | "PATCH" | "DELETE",
    secretName: string | undefined,
    {
      params,
      data,
    }: {
      params?: Record<string, string | undefined>;
      data?: Record<string, unknown>;
    },
    signal: AbortSignal,
  ) => {
    const name =
      secretName === undefined ? "" : `/${encodeURIComponent(secretName)}`;

    if (!useV3SecretRoutes) {
      try {
        return await apiRequest<T>(
          method,
          `/v4/secrets${name}`,
          { params, data },
          signal,
        );
      } catch (err) {
        if (!isRouteNotFound(err)) throw err;

        useV3SecretRoutes = true;
        safeLog({
          level: "warn",
          event: "secrets_api_fallback",
          message:
            "Infisical has no v4 secrets API, so the secret tools use the deprecated v3 routes. Upgrade to v0.150.0 or later.",
        });
      }
    }

    return apiRequest<T>(
      method,
      `/v3/secrets/raw${name}`,
      { params: params && toV3Fields(params), data: data && toV3Fields(data) },
      signal,
    );
  };

  // with masking on, ask for no values at all so none reach this process
  const secretReadParams = (data: {
    projectId: string;
    environmentSlug: string;
    secretPath: string;
    expandSecretReferences: boolean;
    includeImports: boolean;
  }) => ({
    projectId: data.projectId,
    environment: data.environmentSlug,
    secretPath: data.secretPath,
    expandSecretReferences: String(data.expandSecretReferences),
    // v4 reads includeImports, but read include_imports until v0.158.3, as v3
    // still does. both are sent, and each version ignores the one it does not
    // read
    includeImports: String(data.includeImports),
    include_imports: String(data.includeImports),
    viewSecretValue: String(!env.INFISICAL_MASK_SECRET_VALUES),
  });

  const server = new Server(
    {
      name: "Infisical",
      version: packageJson.version,
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  const isToolEnabled = (name: string) =>
    env.INFISICAL_ENABLED_TOOLS.includes(name as AvailableTools);

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: allCapabilities.filter((capability) =>
        isToolEnabled(capability.name),
      ),
    };
  });

  const callTool = async (req: CallToolRequest, signal: AbortSignal) => {
    try {
      const { name, arguments: args } = req.params;

      if (!ALL_TOOLS.includes(name as AvailableTools)) {
        throw new McpError(
          ErrorCode.InvalidParams,
          `Unrecognized tool name: ${name}`,
        );
      }

      // gate before authenticating so a disabled tool never touches credentials
      if (!isToolEnabled(name)) {
        throw new ToolNotEnabledError(
          `Tool "${name}" is not enabled on this server. Enabled tools: ${env.INFISICAL_ENABLED_TOOLS.join(", ")}. Add it to INFISICAL_ENABLED_TOOLS in the server's configuration to enable it.`,
        );
      }

      await handleAuthentication();

      if (name === AvailableTools.CreateSecret) {
        const data = createSecretSchema.zod.parse(args);

        const res = await secretRequest<SecretWriteResponse>(
          "POST",
          data.secretName,
          {
            data: {
              projectId: data.projectId,
              environment: data.environmentSlug,
              secretPath: data.secretPath,
              secretValue: data.secretValue ?? "",
            },
          },
          signal,
        );

        if ("approval" in res) return pendingApproval(res.approval);

        return {
          content: [
            {
              type: "text",
              text: `Secret created successfully: ${JSON.stringify(maskSecret(res.secret), null, 3)}`,
            },
          ],
        };
      }

      if (name === AvailableTools.DeleteSecret) {
        const data = deleteSecretSchema.zod.parse(args);

        const res = await secretRequest<SecretWriteResponse>(
          "DELETE",
          data.secretName,
          {
            data: {
              projectId: data.projectId,
              environment: data.environmentSlug,
              secretPath: data.secretPath,
            },
          },
          signal,
        );

        if ("approval" in res) return pendingApproval(res.approval);

        return {
          content: [
            {
              type: "text",
              text: `Secret deleted successfully: ${res.secret.secretKey}`,
            },
          ],
        };
      }

      if (name === AvailableTools.UpdateSecret) {
        const data = updateSecretSchema.zod.parse(args);

        const res = await secretRequest<SecretWriteResponse>(
          "PATCH",
          data.secretName,
          {
            data: {
              projectId: data.projectId,
              environment: data.environmentSlug,
              secretPath: data.secretPath,
              newSecretName: data.newSecretName,
              // left undefined, it is not sent and the API keeps the value
              secretValue: data.secretValue,
            },
          },
          signal,
        );

        if ("approval" in res) return pendingApproval(res.approval);

        return {
          content: [
            {
              type: "text",
              text: `Secret updated successfully. Updated secret: ${JSON.stringify(maskSecret(res.secret), null, 3)}`,
            },
          ],
        };
      }

      if (name === AvailableTools.ListSecrets) {
        const data = listSecretsSchema.zod.parse(args);

        const secrets = await secretRequest<ListSecretsResponse>(
          "GET",
          undefined,
          { params: secretReadParams(data) },
          signal,
        );

        const response = {
          secrets: secrets.secrets.map((secret) =>
            maskSecret({
              secretKey: secret.secretKey,
              secretValue: secret.secretValue,
            }),
          ),
          ...(secrets.imports && {
            imports: secrets.imports?.map((imp) => {
              const parsedImportSecrets = imp.secrets.map((secret) =>
                maskSecret({
                  secretKey: secret.secretKey,
                  secretValue: secret.secretValue,
                }),
              );

              return {
                ...imp,
                secrets: parsedImportSecrets,
              };
            }),
          }),
        };

        return {
          content: [
            {
              type: "text",
              text: `${JSON.stringify(response)}`,
            },
          ],
        };
      }

      if (name === AvailableTools.GetSecret) {
        const data = getSecretSchema.zod.parse(args);

        const { secret } = await secretRequest<GetSecretResponse>(
          "GET",
          data.secretName,
          { params: secretReadParams(data) },
          signal,
        );

        return {
          content: [
            {
              type: "text",
              text: `Secret retrieved successfully: ${JSON.stringify(maskSecret(secret), null, 3)}`,
            },
          ],
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
          type: data.type,
        });

        return {
          content: [
            {
              type: "text",
              text: `Project created successfully: ${JSON.stringify(project, null, 3)}`,
            },
          ],
        };
      }

      if (name === AvailableTools.CreateEnvironment) {
        const data = createEnvironmentSchema.zod.parse(args);

        const environment = await infisicalSdk.environments().create({
          projectId: data.projectId,
          name: data.name,
          slug: data.slug,
          position: data.position,
        });

        return {
          content: [
            {
              type: "text",
              text: `Environment created successfully: ${JSON.stringify(environment, null, 3)}`,
            },
          ],
        };
      }

      if (name === AvailableTools.CreateFolder) {
        const data = createFolderSchema.zod.parse(args);

        const folder = await infisicalSdk.folders().create({
          description: data.description,
          environment: data.environment,
          name: data.name,
          path: data.path,
          projectId: data.projectId,
        });

        return {
          content: [
            {
              type: "text",
              text: `Folder created successfully: ${JSON.stringify(folder, null, 3)}`,
            },
          ],
        };
      }

      if (name === AvailableTools.InviteMembersToProject) {
        const data = inviteMembersToProjectSchema.zod.parse(args);

        const projectMemberships = await infisicalSdk.projects().inviteMembers({
          projectId: data.projectId,
          emails: data.emails,
          usernames: data.usernames,
          roleSlugs: data.roleSlugs,
        });

        return {
          content: [
            {
              type: "text",
              text: `Members successfully invited to project: ${JSON.stringify(projectMemberships, null, 3)}`,
            },
          ],
        };
      }

      if (name === AvailableTools.ListProjects) {
        const data = listProjectsSchema.zod.parse(args);

        const res = await apiRequest<{
          workspaces: {
            hasDeleteProtection: boolean;
            id: string;
            name: string;
            orgId: string;
            slug: string;
            type: string;
            environments: {
              name: string;
              slug: string;
              id: string;
            }[];
          }[];
        }>(
          "GET",
          "/v1/workspace",
          {
            params: {
              // the API has no "all" type; omitting the filter returns every project
              type: data.type === "all" ? undefined : data.type,
            },
          },
          signal,
        );

        const projects = res.workspaces.map((workspace) => ({
          hasDeleteProtection: workspace.hasDeleteProtection,
          id: workspace.id,
          name: workspace.name,
          orgId: workspace.orgId,
          slug: workspace.slug,
          type: workspace.type,
          environments: workspace.environments.map((environment) => ({
            ...environment,
          })),
        }));

        return {
          content: [
            {
              type: "text",
              text: `Projects retrieved successfully: ${JSON.stringify(projects, null, 3)}`,
            },
          ],
        };
      }

      throw new Error(`Unrecognized tool name: ${name}`);
    } catch (err) {
      if (err instanceof z.ZodError) {
        throw new Error(
          `Invalid arguments: ${err.errors.map((e) => `${e.path.join(".")}: ${e.message}`).join(", ")}`,
        );
      }
      throw err;
    }
  };

  // a universal auth token Infisical rejects, because it was revoked or ran
  // out of uses, is replaced by logging in again, once. a 401 means the call
  // was refused before it did anything, so repeating it is safe. a token from
  // a login made during this call is not retried, since that would not help
  const callToolWithRelogin = async (
    req: CallToolRequest,
    signal: AbortSignal,
  ) => {
    const attemptsBefore = loginAttempts;

    try {
      return await callTool(req, signal);
    } catch (err) {
      const canLogInAgain =
        env.INFISICAL_AUTH_METHOD === InfisicalAuthMethod.UniversalAuth &&
        loginAttempts === attemptsBefore;

      if (!canLogInAgain || !isUnauthorized(err)) throw err;

      isAuthenticated = false;
      return callTool(req, signal);
    }
  };

  // the client ID names the machine identity; the client secret is never logged
  const actor = {
    authMethod: env.INFISICAL_AUTH_METHOD,
    ...(env.INFISICAL_AUTH_METHOD === InfisicalAuthMethod.UniversalAuth && {
      clientId: env.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID,
    }),
  };

  server.setRequestHandler(CallToolRequestSchema, async (req, extra) => {
    const { name, arguments: args } = req.params;
    const startedAt = Date.now();

    const audit = (outcome: "success" | "denied" | "error", error?: string) => {
      if (!env.INFISICAL_AUDIT_LOG) return;

      const client = server.getClientVersion();

      // safeLog, so a failed write to the log cannot turn a call that worked
      // into a failure, or a client might repeat a write that already happened
      safeLog({
        level: { success: "info", denied: "warn", error: "error" }[outcome],
        event: "tool_call",
        tool: name,
        outcome,
        durationMs: Date.now() - startedAt,
        actor,
        client: client && { name: client.name, version: client.version },
        arguments: auditedArguments(args),
        ...(error && { error }),
      });
    };

    try {
      const result = await callToolWithRelogin(req, extra.signal);
      audit("success");
      return result;
    } catch (err) {
      const message = (err as Error).message;

      // an unknown or disabled tool is a protocol error, as the MCP spec
      // asks. a failure while running a tool comes back as a result with
      // isError set, so the model sees the reason and can act on it
      if (err instanceof McpError) {
        audit(err instanceof ToolNotEnabledError ? "denied" : "error", message);
        throw err;
      }

      audit("error", message);
      return {
        isError: true,
        content: [{ type: "text", text: message }],
      };
    }
  });

  return server;
};

// the hardening controls are opt-in, so the startup entry warns when they are
// off, where an operator reading the client's log will see it
export const getStartupLogEntry = (env: Env) => {
  const warnings: string[] = [];

  if (!env.INFISICAL_MASK_SECRET_VALUES) {
    warnings.push(
      "Secret values are returned to the model. Set INFISICAL_MASK_SECRET_VALUES=true to mask them.",
    );
  }

  const mutatingTools = allCapabilities
    .filter((capability) => !capability.annotations.readOnlyHint)
    .map((capability) => capability.name)
    .filter((name) => env.INFISICAL_ENABLED_TOOLS.includes(name));

  if (mutatingTools.length) {
    warnings.push(
      `Tools that change data are enabled: ${mutatingTools.join(", ")}. Set INFISICAL_ENABLED_TOOLS to leave them out.`,
    );
  }

  return {
    level: warnings.length ? "warn" : "info",
    event: "server_started",
    message: "Infisical MCP Server running on stdio",
    version: packageJson.version,
    // origin only, so a URL with credentials or a path in it is not echoed
    host: new URL(env.INFISICAL_HOST_URL).origin,
    authMethod: env.INFISICAL_AUTH_METHOD,
    enabledTools: env.INFISICAL_ENABLED_TOOLS,
    maskSecretValues: env.INFISICAL_MASK_SECRET_VALUES,
    auditLog: env.INFISICAL_AUDIT_LOG,
    ...(warnings.length && { warnings }),
  };
};

// serve over stdio when run directly, rather than imported by the tests
if (require.main === module) {
  const env = getEnvironmentVariables();
  const server = createServer(env);

  (async () => {
    await server.connect(new StdioServerTransport());
    writeLog(getStartupLogEntry(env));
  })();
}
