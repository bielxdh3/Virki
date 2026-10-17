export const DISPLAY_TIME_ZONE = "America/Porto_Velho";
export const DISPLAY_TIME_ZONE_LABEL = "America/Porto_Velho (UTC−4)";
const formatter = new Intl.DateTimeFormat("pt-BR", { timeZone: DISPLAY_TIME_ZONE, day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", hourCycle: "h23" });

export function formatDateTime(value: Date | string): string {
  return `${formatter.format(typeof value === "string" ? new Date(value) : value)} (UTC−4)`;
}
