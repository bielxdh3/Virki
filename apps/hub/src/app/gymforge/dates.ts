export const GYMFORGE_MVP_TIME_ZONE = "America/Sao_Paulo";

const gymForgeDateFormatter = new Intl.DateTimeFormat("en-CA", {
  timeZone: GYMFORGE_MVP_TIME_ZONE,
  year: "numeric",
  month: "2-digit",
  day: "2-digit"
});

export function getGymForgeAttendanceEffectiveDate(now = new Date()): Date {
  const parts = gymForgeDateFormatter.formatToParts(now);
  const year = getDatePart(parts, "year");
  const month = getDatePart(parts, "month");
  const day = getDatePart(parts, "day");

  return new Date(Date.UTC(year, month - 1, day));
}

export function formatGymForgeAttendanceDate(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function getDatePart(parts: Intl.DateTimeFormatPart[], type: "year" | "month" | "day"): number {
  const value = parts.find((part) => part.type === type)?.value;
  const parsed = Number(value);

  if (!Number.isSafeInteger(parsed)) {
    throw new Error("Unable to calculate GymForge attendance date.");
  }

  return parsed;
}
