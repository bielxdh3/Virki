export type CoreProjectActionFeedback =
  | {
      kind: "success";
      code:
        | "created"
        | "updated"
        | "archived"
        | "access-granted"
        | "access-changed"
        | "access-unchanged"
        | "access-revoked";
    }
  | {
      kind: "error";
      code:
        | "elevation"
        | "project-create"
        | "project-update"
        | "project-archive"
        | "project-access";
    };

type QueryValue = string | string[] | undefined;

export function getCoreProjectActionFeedback(searchParams?: {
  status?: QueryValue;
  error?: QueryValue;
}): CoreProjectActionFeedback | null {
  const error = getSingleQueryValue(searchParams?.error);

  switch (error) {
    case "elevation":
    case "project-create":
    case "project-update":
    case "project-archive":
    case "project-access":
      return { kind: "error", code: error };
    default:
      break;
  }

  const status = getSingleQueryValue(searchParams?.status);

  switch (status) {
    case "created":
    case "updated":
    case "archived":
    case "access-granted":
    case "access-changed":
    case "access-unchanged":
    case "access-revoked":
      return { kind: "success", code: status };
    default:
      return null;
  }
}

export function getCoreProjectFeedbackMessage(
  feedback: CoreProjectActionFeedback,
  copy: Record<string, string>
): string {
  const messageKey = `feedback${feedback.code
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("")}`;

  return copy[messageKey] ?? copy.actionError;
}

function getSingleQueryValue(value: QueryValue): string | undefined {
  return typeof value === "string" ? value : undefined;
}
