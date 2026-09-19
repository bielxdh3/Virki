"use client";

import React, { useEffect, useRef, useState } from "react";
import type { BielosLocale } from "@bielos/ui";

const STORAGE_KEY = "bielos-appearance-v1";
const MAX_PAYLOAD_BYTES = 8 * 1024;

const FONT_OPTIONS = ["times", "georgia", "garamond", "arial", "verdana", "trebuchet", "mono"] as const;
const SCALE_OPTIONS = ["90", "95", "100", "105", "110", "115"] as const;
const ACCENT_OPTIONS = ["sand", "sage", "plum"] as const;
const RADIUS_OPTIONS = ["compact", "rounded"] as const;
const SURFACE_OPTIONS = ["neutral", "warm", "paper"] as const;
const CONTRAST_OPTIONS = ["standard", "high"] as const;

type AppearanceState = {
  version: 1;
  font: (typeof FONT_OPTIONS)[number];
  scale: (typeof SCALE_OPTIONS)[number];
  accent: (typeof ACCENT_OPTIONS)[number];
  radius: (typeof RADIUS_OPTIONS)[number];
  surface: (typeof SURFACE_OPTIONS)[number];
  contrast: (typeof CONTRAST_OPTIONS)[number];
  motionScale: number;
  reducedMotion: boolean;
};

const DEFAULT_APPEARANCE: AppearanceState = {
  version: 1,
  font: "times",
  scale: "100",
  accent: "sand",
  radius: "rounded",
  surface: "neutral",
  contrast: "standard",
  motionScale: 100,
  reducedMotion: false
};

const copy = {
  "pt-BR": {
    label: "Aparência",
    font: "Fonte",
    scale: "Escala",
    accent: "Acento",
    radius: "Cantos",
    surface: "Superfície",
    contrast: "Contraste",
    standard: "Padrão",
    high: "Alto",
    motionScale: "Movimento",
    motion: "Reduzir movimento",
    reset: "Restaurar",
    export: "Exportar",
    import: "Importar",
    invalid: "Arquivo inválido.",
    saved: "Preferência salva.",
    times: "Times",
    georgia: "Georgia",
    garamond: "Garamond",
    arial: "Arial",
    verdana: "Verdana",
    trebuchet: "Trebuchet",
    mono: "Mono",
    neutral: "Neutro",
    warm: "Quente",
    paper: "Papel",
    compact: "Compacto",
    rounded: "Arredondado"
  },
  en: {
    label: "Appearance",
    font: "Font",
    scale: "Scale",
    accent: "Accent",
    radius: "Corners",
    surface: "Surface",
    contrast: "Contrast",
    standard: "Default",
    high: "High",
    motionScale: "Motion",
    motion: "Reduce motion",
    reset: "Reset",
    export: "Export",
    import: "Import",
    invalid: "Invalid file.",
    saved: "Preference saved.",
    times: "Times",
    georgia: "Georgia",
    garamond: "Garamond",
    arial: "Arial",
    verdana: "Verdana",
    trebuchet: "Trebuchet",
    mono: "Mono",
    neutral: "Neutral",
    warm: "Warm",
    paper: "Paper",
    compact: "Compact",
    rounded: "Rounded"
  }
} satisfies Record<BielosLocale, Record<string, string>>;

function isChoice<T extends readonly string[]>(value: unknown, choices: T): value is T[number] {
  return typeof value === "string" && choices.includes(value);
}

function parseAppearance(value: unknown): AppearanceState | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  if (record.version !== 1 || typeof record.reducedMotion !== "boolean") return null;
  if (!isChoice(record.font, FONT_OPTIONS) || !isChoice(record.scale, SCALE_OPTIONS)) return null;
  if (!isChoice(record.accent, ACCENT_OPTIONS) || !isChoice(record.radius, RADIUS_OPTIONS)) return null;
  if (!isChoice(record.surface, SURFACE_OPTIONS)) return null;
  const contrast = record.contrast === undefined ? DEFAULT_APPEARANCE.contrast : record.contrast;
  const motionScale = record.motionScale === undefined ? DEFAULT_APPEARANCE.motionScale : record.motionScale;
  if (!isChoice(contrast, CONTRAST_OPTIONS) || typeof motionScale !== "number" || !Number.isFinite(motionScale) || motionScale < 0 || motionScale > 200) return null;
  return {
    version: 1,
    font: record.font,
    scale: record.scale,
    accent: record.accent,
    radius: record.radius,
    surface: record.surface,
    contrast,
    motionScale: Math.round(motionScale),
    reducedMotion: record.reducedMotion
  };
}

function readStoredAppearance(): AppearanceState | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw || new TextEncoder().encode(raw).byteLength > MAX_PAYLOAD_BYTES) return null;
    return parseAppearance(JSON.parse(raw));
  } catch {
    return null;
  }
}

function applyAppearance(state: AppearanceState): void {
  const root = document.documentElement;
  root.dataset.font = state.font;
  root.dataset.fontScale = state.scale;
  root.dataset.accent = state.accent;
  root.dataset.radius = state.radius;
  root.dataset.surface = state.surface;
  root.dataset.contrast = state.contrast;
  root.dataset.motionScale = String(state.motionScale);
  const motionFactor = state.motionScale / 100;
  root.style.setProperty("--motion-scale", String(motionFactor));
  root.style.setProperty("--motion-duration", `${Math.round(150 * motionFactor)}ms`);
  root.style.setProperty("--motion-pulse-duration", `${Math.round(2_800 * motionFactor)}ms`);
  root.style.setProperty("--motion-rise-duration", `${Math.round(420 * motionFactor)}ms`);
  root.dataset.reducedMotion = String(state.reducedMotion);
}

export function AppearanceControls({ locale }: { locale: BielosLocale }) {
  const t = copy[locale];
  const fileInput = useRef<HTMLInputElement>(null);
  const [state, setState] = useState<AppearanceState>(DEFAULT_APPEARANCE);
  const [ready, setReady] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const stored = readStoredAppearance();
    const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
    setState(stored ?? { ...DEFAULT_APPEARANCE, reducedMotion });
    setReady(true);
  }, []);

  useEffect(() => {
    if (!ready) return;
    applyAppearance(state);
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch {
      // A blocked or full local storage must not break the authenticated shell.
    }
  }, [ready, state]);

  function update<K extends keyof AppearanceState>(key: K, value: AppearanceState[K]) {
    setState((current) => ({ ...current, [key]: value }));
    setMessage(t.saved);
  }

  function reset() {
    setState(DEFAULT_APPEARANCE);
    setMessage(t.saved);
  }

  function exportAppearance() {
    const blob = new Blob([JSON.stringify(state)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "bielos-appearance-v1.json";
    link.click();
    URL.revokeObjectURL(url);
  }

  async function importAppearance(file: File | undefined) {
    if (!file || file.size > MAX_PAYLOAD_BYTES) {
      setMessage(t.invalid);
      return;
    }
    try {
      const parsed = parseAppearance(JSON.parse(await file.text()));
      if (!parsed) throw new Error("invalid");
      setState(parsed);
      setMessage(t.saved);
    } catch {
      setMessage(t.invalid);
    }
  }

  return (
    <details id="appearance" className="appearance-control">
      <summary className="button-ghost" aria-label={t.label}>{t.label}</summary>
      <div className="appearance-popover" role="dialog" aria-label={t.label}>
        <div className="appearance-grid">
          <label>{t.font}<select value={state.font} onChange={(event) => update("font", event.target.value as AppearanceState["font"])}>{FONT_OPTIONS.map((value) => <option key={value} value={value}>{t[value]}</option>)}</select></label>
          <label>{t.scale}<select value={state.scale} onChange={(event) => update("scale", event.target.value as AppearanceState["scale"])}>{SCALE_OPTIONS.map((value) => <option key={value} value={value}>{value}%</option>)}</select></label>
          <label>{t.accent}<select value={state.accent} onChange={(event) => update("accent", event.target.value as AppearanceState["accent"])}>{ACCENT_OPTIONS.map((value) => <option key={value} value={value}>{value[0].toUpperCase() + value.slice(1)}</option>)}</select></label>
          <label>{t.radius}<select value={state.radius} onChange={(event) => update("radius", event.target.value as AppearanceState["radius"])}>{RADIUS_OPTIONS.map((value) => <option key={value} value={value}>{t[value]}</option>)}</select></label>
          <label>{t.surface}<select value={state.surface} onChange={(event) => update("surface", event.target.value as AppearanceState["surface"])}>{SURFACE_OPTIONS.map((value) => <option key={value} value={value}>{t[value]}</option>)}</select></label>
          <label>{t.contrast}<select value={state.contrast} onChange={(event) => update("contrast", event.target.value as AppearanceState["contrast"])}>{CONTRAST_OPTIONS.map((value) => <option key={value} value={value}>{t[value]}</option>)}</select></label>
        </div>
        <label className="appearance-range">{t.motionScale}<output htmlFor="appearance-motion">{state.motionScale}%</output><input id="appearance-motion" type="range" min="0" max="200" step="5" value={state.motionScale} onChange={(event) => update("motionScale", Number(event.target.value))} /></label>
        <label className="appearance-toggle"><input type="checkbox" checked={state.reducedMotion} onChange={(event) => update("reducedMotion", event.target.checked)} />{t.motion}</label>
        <div className="appearance-actions">
          <button className="button-ghost" type="button" onClick={reset}>{t.reset}</button>
          <button className="button-ghost" type="button" onClick={exportAppearance}>{t.export}</button>
          <button className="button-ghost" type="button" onClick={() => fileInput.current?.click()}>{t.import}</button>
          <input ref={fileInput} className="sr-only" type="file" accept="application/json" onChange={(event) => { void importAppearance(event.target.files?.[0]); event.target.value = ""; }} />
        </div>
        <span className="sr-only" role="status" aria-live="polite">{message}</span>
      </div>
    </details>
  );
}
