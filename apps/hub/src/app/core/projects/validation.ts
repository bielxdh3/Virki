export const CORE_PROJECT_VISIBILITIES = ["PUBLIC", "INTERNAL", "SENSITIVE"] as const;
export const CORE_PROJECT_EDITABLE_STATUSES = [
  "PLANNED",
  "RESERVED",
  "ACTIVE",
  "PAUSED"
] as const;

type CoreProjectVisibility = (typeof CORE_PROJECT_VISIBILITIES)[number];
type CoreProjectEditableStatus = (typeof CORE_PROJECT_EDITABLE_STATUSES)[number];

export type CoreProjectFields = {
  name: string;
  slug: string;
  description: string;
  visibility: string;
  status: string;
};

export type ValidatedCoreProjectInput = {
  name: string;
  slug: string;
  description: string | null;
  visibility: CoreProjectVisibility;
  status: CoreProjectEditableStatus;
};

export function validateCoreProjectInput(
  fields: CoreProjectFields
): ValidatedCoreProjectInput | null {
  const name = fields.name.trim();
  const slug = fields.slug.trim();
  const description = fields.description.trim();

  if (name.length < 2 || name.length > 80) {
    return null;
  }

  if (
    slug.length < 3 ||
    slug.length > 64 ||
    !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)
  ) {
    return null;
  }

  if (description.length > 500) {
    return null;
  }

  if (!isCoreProjectVisibility(fields.visibility) || !isCoreProjectEditableStatus(fields.status)) {
    return null;
  }

  return {
    name,
    slug,
    description: description || null,
    visibility: fields.visibility,
    status: fields.status
  };
}

function isCoreProjectVisibility(value: string): value is CoreProjectVisibility {
  return CORE_PROJECT_VISIBILITIES.includes(value as CoreProjectVisibility);
}

function isCoreProjectEditableStatus(value: string): value is CoreProjectEditableStatus {
  return CORE_PROJECT_EDITABLE_STATUSES.includes(value as CoreProjectEditableStatus);
}
