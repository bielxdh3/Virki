export type ProjectVisibility = "public" | "internal" | "sensitive";

export type ProjectStatus = "planned" | "reserved" | "active" | "paused" | "archived";

export type BielOsProject = {
  id: string;
  name: string;
  slug: string;
  visibility: ProjectVisibility;
  status: ProjectStatus;
};

export * from "./capabilities";
