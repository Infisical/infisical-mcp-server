#!/usr/bin/env node

import fs from "fs";
import axios from "axios";
import path from "path";
import { setTimeout as sleep } from "timers/promises";
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
  ListFolders = "list-folders",
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

// Infisical creates the one PAM project an organization has by itself, and
// refuses to create another
const CREATE_PROJECT_TYPES = [
  "secret-manager",
  "cert-manager",
  "kms",
  "secret-scanning",
] as const;

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

// lets Infisical count this server's traffic, the way it already recognises
// "k8-operator/<version>"
const USER_AGENT = `infisical-mcp-server/${packageJson.version}`;

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
        .default("https://app.infisical.com")
        // the API is under <host>/api, so the host is kept without a trailing
        // slash or /api, whichever way it was given. only the path is trimmed,
        // so a host that is itself called api keeps its name
        .transform((url) => {
          const parsed = new URL(url);
          parsed.pathname = parsed.pathname
            .replace(/\/+$/, "")
            .replace(/\/api$/, "");
          return parsed.toString().replace(/\/+$/, "");
        }),
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

// renew the access token this long before it expires, or halfway through its
// lifetime if that comes first, so a short TTL is not a renewal per call
const TOKEN_RENEWAL_MARGIN_MS = 60 * 1000;

// when renewing and logging in again both fail, the current token is kept
// while it is still valid, and renewing is tried again this much later
const TOKEN_RENEWAL_RETRY_MS = 10 * 1000;

// work out when to renew from the expiresIn that a login or renewal returns,
// which is relative, so a local clock that disagrees with Infisical's does not
// matter. a token that never expires comes back with an expiresIn of 0
const getTokenTimes = (expiresIn: number | undefined, requestedAt: number) => {
  if (!expiresIn || expiresIn <= 0) {
    return { renewAt: undefined, expiresAt: undefined };
  }

  const lifetimeMs = expiresIn * 1000;
  const marginMs = Math.min(TOKEN_RENEWAL_MARGIN_MS, lifetimeMs / 2);

  return {
    renewAt: requestedAt + lifetimeMs - marginMs,
    expiresAt: requestedAt + lifetimeMs,
  };
};

// a 10 second timeout, and up to four retries with exponential backoff when
// rate limited or when a read gets no response, as the SDK's client does
const API_TIMEOUT_MS = 10 * 1000;
const API_MAX_RETRIES = 4;
const API_RETRY_DELAY_MS = 1000;

// the fields of a secret this server reads. Infisical returns more, which pass
// through to the response as they are
type Secret = { secretKey: string; secretValue: string; [field: string]: unknown };

type GetSecretResponse = { secret: Secret };

type ListSecretsResponse = {
  secrets: Secret[];
  imports?: {
    secretPath: string;
    environment: string;
    folderId?: string;
    secrets: Secret[];
  }[];
};

// a write to an environment with a change policy returns a change request
// instead of the secret, and only takes effect once it is approved
type ChangeRequest = { id: string; slug: string; status: string };

type SecretWriteResponse = { secret: Secret } | { approval: ChangeRequest };

// every tool answers with a single text block
const textResult = (text: string) => ({ content: [{ type: "text", text }] });

type ToolResult = ReturnType<typeof textResult>;

// marks such a result for the audit log. a symbol key is not serialized, so
// the client never sees it
const PENDING_APPROVAL = Symbol("pendingApproval");

const pendingApproval = ({ id, slug, status }: ChangeRequest) => ({
  [PENDING_APPROVAL]: true,
  ...textResult(
    `The change was not applied yet. This environment requires approval for secret changes, so it is waiting in a change request: ${JSON.stringify({ id, slug, status }, null, 3)}`,
  ),
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
// with "Route GET:/api/v4/secrets?... not found". standalone images up to
// v0.100.0 hand unknown paths to the frontend instead, which sends an HTML
// 404 with no message. a 404 for a missing secret always carries one
const isRouteNotFound = (err: unknown) =>
  err instanceof ApiRequestError &&
  err.status === 404 &&
  (err.apiMessage === undefined || /^Route \S+ not found/.test(err.apiMessage));

type HttpMethod = "GET" | "POST" | "PATCH" | "DELETE";

type RequestOptions = {
  params?: Record<string, string | undefined>;
  data?: Record<string, unknown>;
  // send no access token, as for the login itself
  withoutToken?: boolean;
  // a write that is safe to send twice, so it is resent when no response
  // comes back, as a read is
  idempotent?: boolean;
};

// where a secret lives, in the fields every secret route takes
const secretLocation = (data: {
  projectId: string;
  environmentSlug: string;
  secretPath: string;
}) => ({
  projectId: data.projectId,
  environment: data.environmentSlug,
  secretPath: data.secretPath,
});

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

const isUnauthorized = (err: unknown) =>
  err instanceof ApiRequestError && err.status === 401;

// a project as Infisical lists it, with the fields this server returns
type Workspace = {
  id: string;
  name: string;
  slug: string;
  type: string;
  orgId: string;
  hasDeleteProtection: boolean;
  environments?: { id: string; name: string; slug: string }[];
};

const toProject = (workspace: Workspace) => ({
  hasDeleteProtection: workspace.hasDeleteProtection,
  id: workspace.id,
  name: workspace.name,
  orgId: workspace.orgId,
  slug: workspace.slug,
  type: workspace.type,
  environments: (workspace.environments ?? []).map(({ id, name, slug }) => ({
    name,
    slug,
    id,
  })),
});

// the project a tool names, and the environment if it takes one
type Location = { projectId: string; environment?: string };

const inSecretFields = (location: Location) => ({
  projectId: location.projectId,
  environmentSlug: location.environment!,
});

// the project or environment a tool named matches none, or more than one
class LocationNotFoundError extends Error {}

// how Infisical answers a project or environment it does not have, which
// on a secret read reads "Folder with path '/' in environment 'x' was not
// found"
const isLocationNotFound = (err: unknown) =>
  err instanceof ApiRequestError &&
  err.status === 404 &&
  /\b(project|environment)\b[^.]*\bnot found\b/i.test(err.apiMessage ?? "");

const MAX_PROJECTS_IN_ERROR = 25;

const describeProject = (project: Workspace) =>
  `"${project.name}" (ID ${project.id}, slug ${project.slug})`;

// what to do next, for the errors models run into most
const errorHint = (
  err: ApiRequestError,
  args: Record<string, unknown> | undefined,
) => {
  if (err.status !== 404 || !err.apiMessage) return undefined;

  if (/^Folder with path .* not found/i.test(err.apiMessage)) {
    return "Call list-folders to see the folders that exist, or create-folder to create this one.";
  }

  if (/^Secret (with name .* )?not found/i.test(err.apiMessage)) {
    return `There is no secret "${args?.secretName}" in folder "${args?.secretPath ?? "/"}" of environment "${args?.environmentSlug}". Call list-secrets to see the secrets there.`;
  }

  return undefined;
};

// Infisical sends a 422's validation issues as an array in message
const formatApiMessage = (message: unknown) => {
  if (message === undefined || typeof message === "string") return message;
  if (!Array.isArray(message)) return JSON.stringify(message);

  return message
    .map((issue: { path?: unknown[]; message?: string }) =>
      issue?.message === undefined
        ? JSON.stringify(issue)
        : issue.path?.length
          ? `${issue.path.join(".")}: ${issue.message}`
          : issue.message,
    )
    .join("; ");
};

// once the client cancels a call, nothing new is sent for it: not a resend,
// a retry after logging in again, or the same request on a fallback route
const throwIfCancelled = (signal?: AbortSignal) => {
  if (signal?.aborted) throw new Error("The client cancelled the call");
};

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

// a value that travels in the URL path, where a blank one or "." and ".."
// would address a different route
const pathSegmentSchema = (label: string) =>
  z
    .string()
    .refine(
      (value) => value.trim() !== "" && value !== "." && value !== "..",
      `${label} cannot be blank, "." or ".."`,
    );

// Infisical accepts "." as a name, but no URL can reach a secret called
// that, so refuse it before sending anything
const secretNameSchema = pathSegmentSchema("Secret name");

// some models send a boolean or a number as a string, such as "true" or "1"
const booleanArgument = (defaultValue: boolean) =>
  z.preprocess(
    (value) => (value === "true" ? true : value === "false" ? false : value),
    z.boolean().default(defaultValue),
  );

const numberArgument = z.preprocess(
  (value) =>
    typeof value === "string" && value.trim() !== "" && !Number.isNaN(Number(value))
      ? Number(value)
      : value,
  z.number().optional(),
);

// the parameters every tool describes the same way, so a model that learns
// one tool can use the rest
const PROJECT_ID_DESCRIPTION =
  "The ID of the project, from list-projects. A project slug or exact project name also works.";
const ENVIRONMENT_DESCRIPTION =
  "The slug of the environment, such as dev, staging or prod. list-projects shows each project's environments. An environment name such as Production also works.";
const SECRET_PATH_DESCRIPTION =
  'The folder path, such as "/" for the root or "/backend/api" for a nested folder. Defaults to "/".';
const EXPAND_REFERENCES_DESCRIPTION =
  "Replace references to other secrets, such as ${DB_HOST}, with their values (Defaults to true)";
const stringArray = (description: string) => ({
  type: "array",
  items: { type: "string" },
  description,
});

// sent to the client when it connects; clients that support it show it to
// the model before any tool is called
const SERVER_INSTRUCTIONS = [
  'Infisical stores secrets in projects. Each project has environments, usually dev, staging and prod, and each environment holds folders addressed by path: "/" is the root and "/backend/api" a nested folder.',
  "Call list-projects first to find a project's ID and its environment slugs. Tools also accept a project slug or exact name in place of the ID, and an environment name in place of its slug.",
  "list-secrets returns the secrets directly in one folder. Set recursive to true to include every folder below it, or call list-folders to see which folders exist.",
].join("\n\n");

const createSecretSchema = {
  zod: z.object({
    projectId: z.string(),
    environmentSlug: z.string(),
    secretName: secretNameSchema,
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
    description:
      "Create a new secret in a project environment. It goes in the root folder, which always exists, unless secretPath names another folder; create that folder with create-folder first. Fails if a secret with that name already exists there; use update-secret to change it.",
    inputSchema: {
      type: "object",
      properties: {
        projectId: {
          type: "string",
          description: PROJECT_ID_DESCRIPTION,
        },
        environmentSlug: {
          type: "string",
          description: ENVIRONMENT_DESCRIPTION,
        },
        secretName: {
          type: "string",
          description: "The name of the secret, such as DATABASE_URL",
        },
        secretValue: {
          type: "string",
          description: "The value of the secret. Defaults to an empty value",
        },
        secretPath: {
          type: "string",
          description: SECRET_PATH_DESCRIPTION,
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
    secretName: secretNameSchema,
  }),
  capability: {
    name: AvailableTools.DeleteSecret,
    annotations: {
      title: "Delete secret",
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
    },
    description:
      "Delete a secret from one environment and folder. To remove a secret everywhere, call it once per environment.",
    inputSchema: {
      type: "object",
      properties: {
        projectId: {
          type: "string",
          description: PROJECT_ID_DESCRIPTION,
        },
        environmentSlug: {
          type: "string",
          description: ENVIRONMENT_DESCRIPTION,
        },
        secretPath: {
          type: "string",
          description: SECRET_PATH_DESCRIPTION,
        },
        secretName: {
          type: "string",
          description: "The name of the secret to delete",
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
    secretName: secretNameSchema,
    // a rename to such a name would leave the secret unreachable by these tools
    newSecretName: secretNameSchema.optional(),
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
    description:
      "Change an existing secret's value, rename it, or both in one call. Fields left out keep their current value.",
    inputSchema: {
      type: "object",
      properties: {
        projectId: {
          type: "string",
          description: PROJECT_ID_DESCRIPTION,
        },
        environmentSlug: {
          type: "string",
          description: ENVIRONMENT_DESCRIPTION,
        },
        secretName: {
          type: "string",
          description: "The current name of the secret",
        },
        newSecretName: {
          type: "string",
          description: "Set to rename the secret. Leave out to keep its name",
        },
        secretValue: {
          type: "string",
          description: "The new value. Leave out to keep the current value",
        },
        secretPath: {
          type: "string",
          description: SECRET_PATH_DESCRIPTION,
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
    recursive: booleanArgument(false),
    expandSecretReferences: booleanArgument(true),
    includeImports: booleanArgument(true),
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
      "List the secrets in one folder of a project environment, the root folder by default. Secrets in subfolders are left out unless recursive is true; list-folders shows which folders exist.",
    inputSchema: {
      type: "object",
      properties: {
        projectId: {
          type: "string",
          description: PROJECT_ID_DESCRIPTION,
        },
        environmentSlug: {
          type: "string",
          description: ENVIRONMENT_DESCRIPTION,
        },
        secretPath: {
          type: "string",
          description: SECRET_PATH_DESCRIPTION,
        },
        recursive: {
          type: "boolean",
          description:
            "Also list the secrets in every folder below secretPath, each with its secretPath (Defaults to false)",
        },
        expandSecretReferences: {
          type: "boolean",
          description: EXPAND_REFERENCES_DESCRIPTION,
        },
        includeImports: {
          type: "boolean",
          description:
            "Also return the secrets this folder imports from other environments or folders (Defaults to true)",
        },
      },
      required: ["projectId", "environmentSlug"],
    },
  },
};

const getSecretSchema = {
  zod: z.object({
    secretName: secretNameSchema,
    projectId: z.string(),
    environmentSlug: z.string(),
    secretPath: z.string().default("/"),
    expandSecretReferences: booleanArgument(true),
    includeImports: booleanArgument(true),
  }),
  capability: {
    name: AvailableTools.GetSecret,
    annotations: {
      title: "Get secret",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
    },
    description: "Get one secret, with its value, by name.",
    inputSchema: {
      type: "object",
      properties: {
        secretName: {
          type: "string",
          description: "The name of the secret to get",
        },
        projectId: {
          type: "string",
          description: PROJECT_ID_DESCRIPTION,
        },
        environmentSlug: {
          type: "string",
          description: ENVIRONMENT_DESCRIPTION,
        },
        secretPath: {
          type: "string",
          description: SECRET_PATH_DESCRIPTION,
        },
        expandSecretReferences: {
          type: "boolean",
          description: EXPAND_REFERENCES_DESCRIPTION,
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
    type: z.enum(CREATE_PROJECT_TYPES).default("secret-manager"),
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
    description:
      "Create a new project. Projects store secrets unless another type is given, and a secret-manager project starts with the environments dev, staging and prod. The response has the new project's ID and environment slugs, which the other tools take. Infisical allows several projects with the same name, so check list-projects first rather than creating a project again.",
    inputSchema: {
      type: "object",
      properties: {
        projectName: {
          type: "string",
          description: "The name of the project",
        },
        type: {
          type: "string",
          enum: [...CREATE_PROJECT_TYPES],
          description:
            "What the project is for. Defaults to secret-manager, for storing secrets. cert-manager is for certificates and PKI, kms for managing encryption keys with Infisical KMS, and secret-scanning for scanning code for leaked secrets (one per organization).",
        },
        description: {
          type: "string",
          description: "A description of the project",
        },
        slug: {
          type: "string",
          description:
            "A URL-friendly identifier of lowercase letters, numbers and hyphens. When left out, Infisical generates one from the name with a random suffix",
        },
        projectTemplate: {
          type: "string",
          description:
            "The name of a project template to create the project from. Leave out unless the user names one; templates need a paid plan",
        },
        kmsKeyId: {
          type: "string",
          description:
            "The ID of an existing KMS key to encrypt this project's data with. Leave out to use Infisical's default key. This does not create a key",
        },
      },
      required: ["projectName"],
    },
  },
};

const createEnvironmentSchema = {
  zod: z.object({
    projectId: pathSegmentSchema("Project ID"),
    name: z.string(),
    slug: z.string(),
    position: numberArgument,
  }),
  capability: {
    name: AvailableTools.CreateEnvironment,
    annotations: {
      title: "Create environment",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
    description:
      "Add an environment, such as QA, to a project. It starts empty; copy secrets into it with create-secret.",
    inputSchema: {
      type: "object",
      properties: {
        projectId: {
          type: "string",
          description: PROJECT_ID_DESCRIPTION,
        },
        name: {
          type: "string",
          description: "The display name of the environment, such as QA",
        },
        slug: {
          type: "string",
          description:
            "The slug the other tools use for the environment, such as qa. Lowercase letters, numbers and hyphens",
        },
        position: {
          type: "number",
          description:
            "Where the environment appears in the project's list. Defaults to last",
        },
      },

      required: ["projectId", "name", "slug"],
    },
  },
};

const createFolderSchema = {
  zod: z
    .object({
      description: z.string().optional(),
      environmentSlug: z.string().optional(),
      // the name earlier versions advertised, still accepted so existing
      // prompts and clients keep working
      environment: z.string().optional(),
      name: z.string(),
      path: z.string().default("/"),
      projectId: z.string(),
    })
    .refine((data) => (data.environmentSlug ?? data.environment) !== undefined, {
      message: "Invalid input: expected string, received undefined",
      path: ["environmentSlug"],
    }),
  capability: {
    name: AvailableTools.CreateFolder,
    annotations: {
      title: "Create folder",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
    description:
      'Create a folder in a project environment. To create /backend/workers, pass path "/backend" and name "workers"; a missing parent folder such as /backend is created too.',
    inputSchema: {
      type: "object",
      properties: {
        projectId: {
          type: "string",
          description: PROJECT_ID_DESCRIPTION,
        },
        environmentSlug: {
          type: "string",
          description: ENVIRONMENT_DESCRIPTION,
        },
        name: {
          type: "string",
          description:
            "The name of the new folder, without slashes. Letters, numbers, dashes and underscores",
        },
        path: {
          type: "string",
          description:
            'The path of the parent folder to create it in. Defaults to "/", the root',
        },
        description: {
          type: "string",
          description: "A description of the folder",
        },
      },
      required: ["projectId", "environmentSlug", "name"],
    },
  },
};

const listFoldersSchema = {
  zod: z.object({
    projectId: z.string(),
    environmentSlug: z.string(),
    path: z.string().default("/"),
    recursive: booleanArgument(false),
  }),
  capability: {
    name: AvailableTools.ListFolders,
    annotations: {
      title: "List folders",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
    },
    description:
      "List the folders in a project environment, each with the full path that secretPath takes.",
    inputSchema: {
      type: "object",
      properties: {
        projectId: {
          type: "string",
          description: PROJECT_ID_DESCRIPTION,
        },
        environmentSlug: {
          type: "string",
          description: ENVIRONMENT_DESCRIPTION,
        },
        path: {
          type: "string",
          description:
            'The folder to list the folders of. Defaults to "/", the root',
        },
        recursive: {
          type: "boolean",
          description:
            "Also list every folder nested below path (Defaults to false)",
        },
      },
      required: ["projectId", "environmentSlug"],
    },
  },
};

const listProjectsSchema = {
  zod: z.object({
    type: z.enum(LIST_PROJECT_TYPES).default("all"),
    search: z.string().optional(),
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
      "List the projects this server can access, with each project's ID, name, slug, type and environments. Call this first to find the projectId and environment slugs the other tools take.",
    inputSchema: {
      type: "object",
      properties: {
        type: {
          type: "string",
          enum: [...LIST_PROJECT_TYPES],
          description:
            "Only list projects of this type. Defaults to all, which lists every project.",
        },
        search: {
          type: "string",
          description:
            "Only list projects whose name or slug contains this text, ignoring case",
        },
      },
    },
  },
};

const inviteMembersToProjectSchema = {
  zod: z.object({
    projectId: pathSegmentSchema("Project ID"),
    // the cap Infisical puts on an org invite. a bound also lets zod refuse
    // an oversized array before it checks every element
    emails: z.array(z.string()).max(100).optional(),
    usernames: z.array(z.string()).max(100).optional(),
    roleSlugs: z.array(z.string()).max(100).optional(),
  }),
  capability: {
    name: AvailableTools.InviteMembersToProject,
    annotations: {
      title: "Invite members to project",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
    description:
      "Add users to a project with one or more roles. Users who are not yet in the organization are invited to it by email. Users who are already members of the project are left as they are.",
    inputSchema: {
      type: "object",
      properties: {
        projectId: {
          type: "string",
          description: PROJECT_ID_DESCRIPTION,
        },
        emails: stringArray(
          "The email addresses of the users to add. Either emails or usernames must be provided.",
        ),
        usernames: stringArray(
          "The usernames of the users to add. Either emails or usernames must be provided.",
        ),
        roleSlugs: stringArray(
          "The roles to give them. The built-in roles are admin, member, viewer and no-access, and a project can define custom roles. Defaults to member.",
        ),
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
  listFoldersSchema.capability,
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
  let accessToken: string | undefined;
  let renewTokenAt: number | undefined;
  let tokenExpiresAt: number | undefined;
  let pendingLogin: Promise<void> | undefined;

  const useToken = (
    token: { accessToken: string; expiresIn?: number },
    requestedAt: number,
  ) => {
    const { renewAt, expiresAt } = getTokenTimes(token.expiresIn, requestedAt);
    accessToken = token.accessToken;
    renewTokenAt = renewAt;
    tokenExpiresAt = expiresAt;
  };

  const logIn = async () => {
    switch (env.INFISICAL_AUTH_METHOD) {
      case InfisicalAuthMethod.UniversalAuth: {
        const requestedAt = Date.now();
        // the login carries no token, since Infisical refuses a login that
        // carries a revoked or used-up one
        const login = await apiRequest<{
          accessToken: string;
          expiresIn?: number;
        }>("POST", "/v1/auth/universal-auth/login", {
          data: {
            clientId: env.INFISICAL_UNIVERSAL_AUTH_CLIENT_ID,
            clientSecret: env.INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET,
          },
          withoutToken: true,
          // a second login only issues another token
          idempotent: true,
        });
        useToken(login, requestedAt);
        break;
      }
      case InfisicalAuthMethod.TokenAuth:
        accessToken = env.INFISICAL_TOKEN!;
        break;
      default:
        throw new Error(
          `Unsupported authentication method: ${env.INFISICAL_AUTH_METHOD}`,
        );
    }

    isAuthenticated = true;
  };

  // renewing extends the token's lifetime, up to its max TTL, without a login,
  // and a login spends one of the client secret's uses when it has a limit
  const renewToken = async () => {
    const requestedAt = Date.now();
    const renewed = await apiRequest<{
      accessToken: string;
      expiresIn?: number;
    }>("POST", "/v1/auth/token/renew", {
      data: { accessToken },
      withoutToken: true,
      idempotent: true,
    });
    useToken(renewed, requestedAt);
  };

  // Infisical refuses to renew a token past its max TTL, and then the server
  // logs in again. if that fails too, the token in hand still works until it
  // expires, so it is kept, and renewing is tried again shortly
  const renewOrLogIn = async () => {
    try {
      await renewToken();
      return;
    } catch {
      // logging in again covers every reason renewing can fail
    }

    try {
      await logIn();
    } catch (err) {
      const now = Date.now();
      if (tokenExpiresAt === undefined || now >= tokenExpiresAt) throw err;

      renewTokenAt = Math.min(now + TOKEN_RENEWAL_RETRY_MS, tokenExpiresAt);
      safeLog({
        level: "warn",
        event: "token_renewal_failed",
        message: `Could not renew the access token or log in again, so the current token is used until it expires: ${(err as Error).message}`,
      });
    }
  };

  const handleAuthentication = async () => {
    const isRenewalDue =
      renewTokenAt !== undefined && Date.now() >= renewTokenAt;

    if (isAuthenticated && !isRenewalDue) {
      return;
    }

    // calls that arrive while a login is under way wait for it, rather than
    // each spending a login of their own. a token that was dropped after a
    // 401 is replaced by a login, since Infisical refused it
    if (!pendingLogin) {
      pendingLogin = (async () => {
        try {
          await (isAuthenticated ? renewOrLogIn() : logIn());
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

  const apiUrl = (route: string) => `${env.INFISICAL_HOST_URL}/api${route}`;

  const apiRequest = async <T>(
    method: HttpMethod,
    route: string,
    { params, data, withoutToken, idempotent }: RequestOptions,
    signal?: AbortSignal,
  ) => {
    // a write may already have been applied when no response comes back, so
    // it is never resent then, only after a 429, which means nothing was done.
    // nor is a write in flight abandoned when the client cancels, so the audit
    // log records what actually happened
    const isRead = method === "GET";

    for (let attempt = 0; ; attempt++) {
      throwIfCancelled(signal);

      try {
        const res = await axios.request<T>({
          method,
          url: apiUrl(route),
          params,
          data,
          signal: isRead ? signal : undefined,
          timeout: requestTimeoutMs,
          headers: {
            "User-Agent": USER_AGENT,
            ...(!withoutToken && { Authorization: `Bearer ${accessToken}` }),
          },
        });

        return res.data;
      } catch (err) {
        if (!axios.isAxiosError(err)) throw err;

        // a cancelled call also arrives without a response, but is not retried
        const isRetryable =
          !axios.isCancel(err) &&
          (err.response?.status === 429 ||
            ((isRead || idempotent) && err.response === undefined));

        if (isRetryable && attempt < API_MAX_RETRIES) {
          const delay = retryDelayMs * 2 ** attempt;
          const jitter = (Math.random() * 2 - 1) * delay * 0.2;
          try {
            await sleep(delay + jitter, undefined, { signal });
          } catch {
            throwIfCancelled(signal);
          }
          continue;
        }

        // rethrow a plain error, since an axios error carries the request
        // config and the bearer token with it
        if (!err.response) throw new Error(err.message);

        const apiMessage = formatApiMessage(
          (err.response.data as { message?: unknown } | undefined)?.message,
        );
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
  // for the rest of the session. a 404 page with no API message, which is
  // how the oldest images answer, could also come from a proxy in front of a
  // current Infisical, so it only sends that one call to the v3 route
  let useV3SecretRoutes = false;
  let loggedV3Fallback = false;

  const secretRequest = async <T>(
    method: HttpMethod,
    secretName: string | undefined,
    { params, data }: RequestOptions,
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

        const saidByInfisical = (err as ApiRequestError).apiMessage !== undefined;
        if (saidByInfisical) useV3SecretRoutes = true;

        // calls already in flight can each land here; log the fallback once
        if (!loggedV3Fallback) {
          loggedV3Fallback = true;
          safeLog({
            level: "warn",
            event: "secrets_api_fallback",
            message: saidByInfisical
              ? "Infisical has no v4 secrets API, so the secret tools use the deprecated v3 routes. Upgrade to v0.150.0 or later."
              : "Infisical answered the v4 secrets route with a 404 page instead of an API error, so the call used the deprecated v3 route. Self-hosted versions up to v0.100.0 answer that way; on a newer version, check whether a proxy in front of Infisical sent the 404.",
          });
        }
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
    ...secretLocation(data),
    expandSecretReferences: String(data.expandSecretReferences),
    // v4 reads includeImports, but read include_imports until v0.158.3, as v3
    // still does. both are sent, and each version ignores the one it does not
    // read
    includeImports: String(data.includeImports),
    include_imports: String(data.includeImports),
    viewSecretValue: String(!env.INFISICAL_MASK_SECRET_VALUES),
  });

  // models often name a project by its name, or an environment as
  // "production" where the slug is prod. that is only looked up once
  // Infisical says the project or environment does not exist, so a call that
  // gets them right costs no extra request
  const resolveLocation = async (
    location: Location,
    signal: AbortSignal,
  ): Promise<Location> => {
    const { workspaces } = await apiRequest<{ workspaces: Workspace[] }>(
      "GET",
      "/v1/workspace",
      {},
      signal,
    );

    const wanted = location.projectId.trim();
    const named = workspaces.filter(
      (workspace) => workspace.name.toLowerCase() === wanted.toLowerCase(),
    );
    const project =
      workspaces.find(
        (workspace) => workspace.id === wanted || workspace.slug === wanted,
      ) ?? (named.length === 1 ? named[0] : undefined);

    if (!project && named.length > 1) {
      throw new LocationNotFoundError(
        `Several projects are named "${wanted}": ${named.map(describeProject).join(", ")}. Pass the ID of the one you mean as projectId.`,
      );
    }

    if (!project) {
      const listed = workspaces.slice(0, MAX_PROJECTS_IN_ERROR);
      const more = workspaces.length - listed.length;
      throw new LocationNotFoundError(
        workspaces.length
          ? `No project has the ID, slug or name "${wanted}". The projects this server can access are ${listed.map(describeProject).join(", ")}${more ? `, and ${more} more that list-projects shows` : ""}.`
          : `No project has the ID, slug or name "${wanted}", and this server cannot access any project.`,
      );
    }

    if (location.environment === undefined) return { projectId: project.id };

    const environments = project.environments ?? [];
    const wantedEnvironment = location.environment.trim().toLowerCase();
    const namedEnvironments = environments.filter(
      (environment) => environment.name.toLowerCase() === wantedEnvironment,
    );
    const environment =
      environments.find(
        (environment) => environment.slug.toLowerCase() === wantedEnvironment,
      ) ?? (namedEnvironments.length === 1 ? namedEnvironments[0] : undefined);

    if (!environment) {
      throw new LocationNotFoundError(
        `Project ${describeProject(project)} has no environment "${location.environment}". Its environments are ${environments.map((environment) => `${environment.slug} (${environment.name})`).join(", ")}.`,
      );
    }

    return { projectId: project.id, environment: environment.slug };
  };

  // runs a call, and when Infisical does not know the project or environment
  // it names, runs it once more with the ones they resolve to. Infisical
  // changed nothing when it answered that, so a write is safe to repeat
  const inLocation = async <R extends ToolResult>(
    location: Location,
    signal: AbortSignal,
    run: (location: Location) => Promise<R>,
  ): Promise<R> => {
    try {
      return await run(location);
    } catch (err) {
      if (!isLocationNotFound(err)) throw err;

      let resolved: Location;
      try {
        resolved = await resolveLocation(location, signal);
      } catch (lookupErr) {
        // when the projects cannot be listed, Infisical's own answer says more
        if (lookupErr instanceof LocationNotFoundError) throw lookupErr;
        throw err;
      }

      // both exist as given, so it was a folder or secret that was missing
      if (
        resolved.projectId === location.projectId &&
        resolved.environment === location.environment
      ) {
        throw err;
      }

      const result = await run(resolved);

      // the model learns the values to pass, so later calls are not repeated
      const used = [
        resolved.projectId !== location.projectId &&
          `projectId "${resolved.projectId}" for "${location.projectId}"`,
        resolved.environment !== location.environment &&
          `environmentSlug "${resolved.environment}" for "${location.environment}"`,
      ].filter(Boolean);

      return {
        ...result,
        content: [
          ...result.content,
          {
            type: "text",
            text: `Note: used ${used.join(" and ")}. Pass these values in later calls.`,
          },
        ],
      };
    }
  };

  const server = new Server(
    {
      name: "Infisical",
      version: packageJson.version,
    },
    {
      capabilities: {
        tools: {},
      },
      instructions: SERVER_INSTRUCTIONS,
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

      // gate before authenticating so a disabled tool never touches credentials.
      // the model reads this message, so it does not say how to enable the
      // tool; the audit log records the refusal for the operator
      if (!isToolEnabled(name)) {
        throw new ToolNotEnabledError(
          `Tool "${name}" is not enabled on this server. Enabled tools: ${env.INFISICAL_ENABLED_TOOLS.join(", ")}.`,
        );
      }

      await handleAuthentication();

      if (name === AvailableTools.CreateSecret) {
        const data = createSecretSchema.zod.parse(args);

        return await inLocation(
          { projectId: data.projectId, environment: data.environmentSlug },
          signal,
          async (location) => {
            const res = await secretRequest<SecretWriteResponse>(
              "POST",
              data.secretName,
              {
                data: {
                  ...secretLocation({ ...data, ...inSecretFields(location) }),
                  secretValue: data.secretValue ?? "",
                },
              },
              signal,
            );

            if ("approval" in res) return pendingApproval(res.approval);

            return textResult(`Secret created successfully: ${JSON.stringify(maskSecret(res.secret), null, 3)}`);
          },
        );
      }

      if (name === AvailableTools.DeleteSecret) {
        const data = deleteSecretSchema.zod.parse(args);

        return await inLocation(
          { projectId: data.projectId, environment: data.environmentSlug },
          signal,
          async (location) => {
            const res = await secretRequest<SecretWriteResponse>(
              "DELETE",
              data.secretName,
              {
                data: secretLocation({ ...data, ...inSecretFields(location) }),
              },
              signal,
            );

            if ("approval" in res) return pendingApproval(res.approval);

            return textResult(`Secret deleted successfully: ${res.secret.secretKey}`);
          },
        );
      }

      if (name === AvailableTools.UpdateSecret) {
        const data = updateSecretSchema.zod.parse(args);

        return await inLocation(
          { projectId: data.projectId, environment: data.environmentSlug },
          signal,
          async (location) => {
            const res = await secretRequest<SecretWriteResponse>(
              "PATCH",
              data.secretName,
              {
                data: {
                  ...secretLocation({ ...data, ...inSecretFields(location) }),
                  newSecretName: data.newSecretName,
                  // left undefined, it is not sent and the API keeps the value
                  secretValue: data.secretValue,
                },
              },
              signal,
            );

            if ("approval" in res) return pendingApproval(res.approval);

            return textResult(`Secret updated successfully. Updated secret: ${JSON.stringify(maskSecret(res.secret), null, 3)}`);
          },
        );
      }

      if (name === AvailableTools.ListSecrets) {
        const data = listSecretsSchema.zod.parse(args);

        return await inLocation(
          { projectId: data.projectId, environment: data.environmentSlug },
          signal,
          async (location) => {
            const secrets = await secretRequest<ListSecretsResponse>(
              "GET",
              undefined,
              {
                params: {
                  ...secretReadParams({ ...data, ...inSecretFields(location) }),
                  recursive: String(data.recursive),
                },
              },
              signal,
            );

            // with recursive set the secrets come from several folders, so
            // each says which one
            const toListed = (secret: Secret) =>
              maskSecret({
                secretKey: secret.secretKey,
                secretValue: secret.secretValue,
                ...(data.recursive && { secretPath: secret.secretPath }),
              });

            const response = {
              secrets: secrets.secrets.map(toListed),
              ...(secrets.imports && {
                imports: secrets.imports?.map((imp) => ({
                  ...imp,
                  secrets: imp.secrets.map(toListed),
                })),
              }),
            };

            return textResult(`${JSON.stringify(response)}`);
          },
        );
      }

      if (name === AvailableTools.GetSecret) {
        const data = getSecretSchema.zod.parse(args);

        return await inLocation(
          { projectId: data.projectId, environment: data.environmentSlug },
          signal,
          async (location) => {
            const { secret } = await secretRequest<GetSecretResponse>(
              "GET",
              data.secretName,
              {
                params: secretReadParams({ ...data, ...inSecretFields(location) }),
              },
              signal,
            );

            return textResult(`Secret retrieved successfully: ${JSON.stringify(maskSecret(secret), null, 3)}`);
          },
        );
      }

      if (name === AvailableTools.CreateProject) {
        const data = createProjectSchema.zod.parse(args);

        const { project } = await apiRequest<{ project: Workspace }>(
          "POST",
          "/v2/workspace",
          {
            data: {
              projectName: data.projectName,
              projectDescription: data.description,
              kmsKeyId: data.kmsKeyId,
              slug: data.slug,
              template: data.projectTemplate,
              type: data.type,
            },
          },
          signal,
        );

        return textResult(`Project created successfully: ${JSON.stringify(toProject(project), null, 3)}`);
      }

      if (name === AvailableTools.CreateEnvironment) {
        const data = createEnvironmentSchema.zod.parse(args);

        return await inLocation(
          { projectId: data.projectId },
          signal,
          async (location) => {
            const { environment } = await apiRequest<{ environment: unknown }>(
              "POST",
              `/v1/workspace/${encodeURIComponent(location.projectId)}/environments`,
              {
                data: {
                  name: data.name,
                  slug: data.slug,
                  position: data.position,
                },
              },
              signal,
            );

            return textResult(`Environment created successfully: ${JSON.stringify(environment, null, 3)}`);
          },
        );
      }

      if (name === AvailableTools.CreateFolder) {
        const data = createFolderSchema.zod.parse(args);

        return await inLocation(
          {
            projectId: data.projectId,
            environment: (data.environmentSlug ?? data.environment)!,
          },
          signal,
          async (location) => {
            const { folder } = await apiRequest<{ folder: unknown }>(
              "POST",
              "/v1/folders",
              {
                data: {
                  workspaceId: location.projectId,
                  environment: location.environment,
                  name: data.name,
                  path: data.path,
                  description: data.description,
                },
              },
              signal,
            );

            return textResult(`Folder created successfully: ${JSON.stringify(folder, null, 3)}`);
          },
        );
      }

      if (name === AvailableTools.ListFolders) {
        const data = listFoldersSchema.zod.parse(args);
        const parentPath = data.path.replace(/^\/*/, "/").replace(/\/+$/, "");

        return await inLocation(
          { projectId: data.projectId, environment: data.environmentSlug },
          signal,
          async (location) => {
            const { folders } = await apiRequest<{
              folders: { name: string; relativePath?: string }[];
            }>(
              "GET",
              "/v1/folders",
              {
                params: {
                  workspaceId: location.projectId,
                  environment: location.environment,
                  path: parentPath || "/",
                  recursive: String(data.recursive),
                },
              },
              signal,
            );

            // a recursive listing gives each folder's path below the one
            // listed, which secretPath needs in full
            const response = {
              folders: folders.map((folder) => ({
                name: folder.name,
                path: `${parentPath}${folder.relativePath ?? `/${folder.name}`}`,
              })),
            };

            return textResult(JSON.stringify(response));
          },
        );
      }

      if (name === AvailableTools.InviteMembersToProject) {
        const data = inviteMembersToProjectSchema.zod.parse(args);

        if (!data.emails?.length && !data.usernames?.length) {
          throw new Error("Either usernames or emails must be provided");
        }

        return await inLocation(
          { projectId: data.projectId },
          signal,
          async (location) => {
            const { memberships } = await apiRequest<{
              memberships: unknown[];
            }>(
              "POST",
              `/v2/workspace/${encodeURIComponent(location.projectId)}/memberships`,
              {
                data: {
                  emails: data.emails,
                  usernames: data.usernames,
                  roleSlugs: data.roleSlugs,
                },
              },
              signal,
            );

            // Infisical skips users who are already members, without saying so
            if (!memberships.length) {
              return textResult(
                "Infisical added no new members. Users who are already members of the project keep the roles they have.",
              );
            }

            return textResult(`Members successfully invited to project with the role(s) ${(data.roleSlugs?.length ? data.roleSlugs : ["member"]).join(", ")}: ${JSON.stringify(memberships, null, 3)}`);
          },
        );
      }

      if (name === AvailableTools.ListProjects) {
        const data = listProjectsSchema.zod.parse(args);

        const res = await apiRequest<{ workspaces: Workspace[] }>(
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

        const search = data.search?.trim().toLowerCase();
        const projects = search
          ? res.workspaces.filter(
              (workspace) =>
                workspace.name.toLowerCase().includes(search) ||
                workspace.slug.toLowerCase().includes(search),
            )
          : res.workspaces;

        return textResult(`Projects retrieved successfully: ${JSON.stringify(projects.map(toProject), null, 3)}`);
      }

      // unknown names are refused above, so this only catches a tool added to
      // AvailableTools without a branch here
      throw new Error(`Unrecognized tool name: ${name}`);
    } catch (err) {
      if (err instanceof z.ZodError) {
        throw new Error(
          `Invalid arguments: ${err.issues.map((e) => `${e.path.join(".")}: ${e.message}`).join(", ")}`,
        );
      }

      const hint = err instanceof ApiRequestError && errorHint(err, req.params.arguments);
      if (hint) throw new Error(`${(err as Error).message}. ${hint}`);

      throw err;
    }
  };

  // a universal auth token Infisical rejects, because it was revoked or ran
  // out of uses, is replaced by logging in again, once. a 401 means the call
  // was refused before it did anything, so repeating it is safe. a call that
  // began without a token got a fresh one from its own login, and is not
  // retried, since logging in again would not help
  const callToolWithRelogin = async (
    req: CallToolRequest,
    signal: AbortSignal,
  ) => {
    const tokenBefore = isAuthenticated ? accessToken : null;

    try {
      return await callTool(req, signal);
    } catch (err) {
      const canLogInAgain =
        env.INFISICAL_AUTH_METHOD === InfisicalAuthMethod.UniversalAuth &&
        tokenBefore !== null;

      if (!canLogInAgain || !isUnauthorized(err)) throw err;

      // calls that sent the same token fail together. the first to get here
      // drops it, and the rest find a new one, or the login under way for it
      if (accessToken === tokenBefore) {
        isAuthenticated = false;
      }

      // checked before logging in, which would also be wasted
      throwIfCancelled(signal);
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

    const audit = (
      outcome: "success" | "pending_approval" | "denied" | "error",
      error?: string,
    ) => {
      if (!env.INFISICAL_AUDIT_LOG) return;

      const client = server.getClientVersion();

      // safeLog, so a failed write to the log cannot turn a call that worked
      // into a failure, or a client might repeat a write that already happened
      safeLog({
        level: {
          success: "info",
          pending_approval: "info",
          denied: "warn",
          error: "error",
        }[outcome],
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
      audit(PENDING_APPROVAL in result ? "pending_approval" : "success");
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
      return { isError: true, ...textResult(message) };
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
  // logs are best effort. a client that closes its end of stderr makes the
  // next write fail with EPIPE, which with no listener crashes the server
  process.stderr.on("error", () => {});

  const env = getEnvironmentVariables();
  const server = createServer(env);

  (async () => {
    await server.connect(new StdioServerTransport());
    writeLog(getStartupLogEntry(env));
  })();
}
