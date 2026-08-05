import type { BielosLocale } from "@bielos/ui";

export type TrustedDeviceCopy = {
  title: string;
  empty: string;
  defaultLabel: string;
  lastSeen: string;
  created: string;
  revoke: string;
};

export type TrustedDeviceDisplay = {
  label: string;
  lastSeen: string;
  created: string;
};

const copy = {
  "pt-BR": {
    title: "Dispositivos confiáveis",
    empty: "Nenhum dispositivo confiável está registrado.",
    defaultLabel: "Dispositivo confiável",
    lastSeen: "Visto por último",
    created: "Registrado",
    revoke: "Revogar"
  },
  en: {
    title: "Trusted devices",
    empty: "No trusted devices are registered.",
    defaultLabel: "Trusted device",
    lastSeen: "Last seen",
    created: "Registered",
    revoke: "Revoke"
  }
} satisfies Record<BielosLocale, TrustedDeviceCopy>;

export function getTrustedDeviceCopy(locale: BielosLocale): TrustedDeviceCopy {
  return copy[locale];
}

export function getTrustedDeviceDisplay(
  device: { label: string | null; lastSeenAt: Date; createdAt: Date },
  locale: BielosLocale
): TrustedDeviceDisplay {
  const labels = copy[locale];
  const formatter = new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" });

  return {
    label: device.label?.trim() || labels.defaultLabel,
    lastSeen: formatter.format(device.lastSeenAt),
    created: formatter.format(device.createdAt)
  };
}
