"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import type { BielosLocale } from "@bielos/ui";

type PaletteEntry = { label: string; hint: string; href: string };
const RECENT_STORAGE_KEY = "bielos-command-recent-v1";
const MAX_RECENT_ENTRIES = 8;

const copy = {
  "pt-BR": { open: "Comandos", placeholder: "Abrir…", close: "Fechar", empty: "Nada encontrado", hint: "Ctrl K" },
  en: { open: "Commands", placeholder: "Open…", close: "Close", empty: "No matches", hint: "Ctrl K" }
} satisfies Record<BielosLocale, Record<string, string>>;

function paletteEntryKey(entry: PaletteEntry): string {
  return `${entry.href}\u0000${entry.label}`;
}

export function rankPaletteEntries(
  entries: readonly PaletteEntry[],
  query: string,
  recentKeys: readonly string[] = [],
  locale: BielosLocale = "pt-BR"
): PaletteEntry[] {
  const language = locale === "pt-BR" ? "pt-BR" : "en";
  const normalized = query.trim().toLocaleLowerCase(language);
  const recentIndex = new Map(recentKeys.map((key, index) => [key, index]));
  return entries
    .map((entry, baseIndex) => {
      const label = entry.label.toLocaleLowerCase(language);
      const haystack = `${entry.label} ${entry.hint}`.toLocaleLowerCase(language);
      if (normalized && !haystack.includes(normalized)) return null;
      const relevance = !normalized
        ? 0
        : label === normalized
          ? 1000
          : label.startsWith(normalized)
            ? 800 - label.length
            : haystack.startsWith(normalized)
              ? 600 - haystack.length
              : 400 - haystack.indexOf(normalized);
      const recent = recentIndex.has(paletteEntryKey(entry))
        ? 100 - (recentIndex.get(paletteEntryKey(entry)) ?? 0)
        : 0;
      return { entry, score: relevance + recent, baseIndex };
    })
    .filter((item): item is { entry: PaletteEntry; score: number; baseIndex: number } => item !== null)
    .sort((left, right) => right.score - left.score || left.baseIndex - right.baseIndex)
    .map((item) => item.entry);
}

function getEntries(locale: BielosLocale, owner: boolean): PaletteEntry[] {
  const pt = locale === "pt-BR";
  const entries: PaletteEntry[] = [
    { label: pt ? "Hub" : "Hub", hint: pt ? "Visão geral" : "Overview", href: "/" },
    { label: pt ? "Projetos" : "Projects", hint: pt ? "Acesso e ciclo de vida" : "Access and lifecycle", href: "/core/projects" },
    { label: pt ? "Módulos" : "Modules", hint: pt ? "Catálogo e pedidos" : "Catalog and requests", href: "/core/modules" },
    { label: pt ? "Saúde" : "Health", hint: pt ? "Estado dos projetos" : "Project status", href: "/core/health" },
    { label: pt ? "Atividade" : "Activity", hint: pt ? "Eventos que precisam de atenção" : "Events that need attention", href: "/core/activity" },
    { label: pt ? "Recuperação" : "Recovery", hint: pt ? "Backup e restore" : "Backup and restore", href: "/core/recovery" },
    { label: pt ? "Segurança" : "Security", hint: pt ? "Sessões e auditoria" : "Sessions and audit", href: "/core/security" },
    { label: pt ? "Aparência" : "Appearance", hint: pt ? "Preferências locais" : "Local preferences", href: "#appearance" }
  ];
  if (owner) entries.push({ label: pt ? "Pedidos" : "Requests", hint: pt ? "Revisão de contas" : "Account review", href: "/core/applications" });
  return entries;
}

export function CommandPalette({ locale, role }: { locale: BielosLocale; role: string }) {
  const t = copy[locale];
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [remoteEntries, setRemoteEntries] = useState<PaletteEntry[]>([]);
  const [recentKeys, setRecentKeys] = useState<string[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const wasOpenRef = useRef(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const entries = useMemo(() => getEntries(locale, role === "OWNER"), [locale, role]);
  const candidates = useMemo(() => {
    const seen = new Set<string>();
    return [...entries, ...remoteEntries].filter((entry) => {
      const key = `${entry.href}\u0000${entry.label}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [entries, remoteEntries]);
  const filtered = useMemo(() => {
    return rankPaletteEntries(candidates, query, recentKeys, locale);
  }, [candidates, locale, query, recentKeys]);

  useEffect(() => {
    try {
      const parsed = JSON.parse(window.localStorage.getItem(RECENT_STORAGE_KEY) ?? "null");
      if (Array.isArray(parsed)) {
        setRecentKeys(parsed.filter((value): value is string => typeof value === "string").slice(0, MAX_RECENT_ENTRIES));
      }
    } catch {
      setRecentKeys([]);
    }
  }, []);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen(true);
      }
      if (event.key === "Escape") setOpen(false);
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (open) {
      setQuery("");
      setRemoteEntries([]);
      setActiveIndex(0);
      window.setTimeout(() => inputRef.current?.focus(), 0);
    } else if (wasOpenRef.current) {
      triggerRef.current?.focus();
    }
    wasOpenRef.current = open;
  }, [open]);

  useEffect(() => {
    const normalized = query.trim();
    if (!open || normalized.length === 0) {
      setRemoteEntries([]);
      return;
    }
    const controller = new AbortController();
    void fetch(`/api/core/command?q=${encodeURIComponent(normalized)}`, { signal: controller.signal, headers: { accept: "application/json" } })
      .then((response) => response.ok ? response.json() as Promise<{ items?: unknown }> : { items: [] })
      .then((payload) => {
        const next = Array.isArray(payload.items) ? payload.items.filter((item): item is PaletteEntry => Boolean(item && typeof item === "object" && typeof (item as PaletteEntry).label === "string" && typeof (item as PaletteEntry).hint === "string" && typeof (item as PaletteEntry).href === "string" && ((item as PaletteEntry).href.startsWith("/") || (item as PaletteEntry).href.startsWith("#")))) : [];
        setRemoteEntries(next);
      })
      .catch(() => { if (!controller.signal.aborted) setRemoteEntries([]); });
    return () => controller.abort();
  }, [open, query]);

  function close() {
    setOpen(false);
  }

  function rememberEntry(entry: PaletteEntry) {
    const key = paletteEntryKey(entry);
    setRecentKeys((current) => {
      const next = [key, ...current.filter((value) => value !== key)].slice(0, MAX_RECENT_ENTRIES);
      try {
        window.localStorage.setItem(RECENT_STORAGE_KEY, JSON.stringify(next));
      } catch {
        // Local recency is an enhancement; navigation must continue if storage is unavailable.
      }
      return next;
    });
  }

  function activateEntry(entry: PaletteEntry, event?: React.MouseEvent<HTMLAnchorElement>) {
    rememberEntry(entry);
    if (entry.href === "#appearance") {
      event?.preventDefault();
      const appearance = document.getElementById("appearance");
      if (appearance instanceof HTMLDetailsElement) {
        appearance.open = true;
        appearance.scrollIntoView({ block: "nearest" });
      }
      close();
      return;
    }
    close();
  }

  function trapDialogFocus(event: React.KeyboardEvent<HTMLElement>) {
    if (event.key !== "Tab") return;
    const focusable = Array.from(event.currentTarget.querySelectorAll<HTMLElement>("button, input, a[href]"))
      .filter((element) => !element.hasAttribute("disabled") && element.getAttribute("aria-hidden") !== "true");
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable.at(-1);
    if (!last) return;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  return (
    <>
      <button ref={triggerRef} className="command-trigger button-ghost" type="button" onClick={() => setOpen(true)} aria-haspopup="dialog" aria-expanded={open}>
        {t.open}<kbd>{t.hint}</kbd>
      </button>
      {open ? (
        <div className="command-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) close(); }}>
          <section className="command-dialog" role="dialog" aria-modal="true" aria-label={t.open} onKeyDown={trapDialogFocus}>
            <div className="command-search-row">
              <input ref={inputRef} value={query} onChange={(event) => { setQuery(event.target.value); setActiveIndex(0); }} onKeyDown={(event) => {
                if (event.key === "ArrowDown") { event.preventDefault(); setActiveIndex((index) => filtered.length ? (index + 1) % filtered.length : 0); }
                if (event.key === "ArrowUp") { event.preventDefault(); setActiveIndex((index) => filtered.length ? (index - 1 + filtered.length) % filtered.length : 0); }
                if (event.key === "Enter" && filtered[activeIndex]) { event.preventDefault(); const entry = filtered[activeIndex]; if (entry.href === "#appearance") activateEntry(entry); else { rememberEntry(entry); window.location.href = entry.href; } }
              }} placeholder={t.placeholder} aria-label={t.placeholder} aria-controls="command-results" aria-activedescendant={filtered[activeIndex] ? `command-option-${activeIndex}` : undefined} />
              <button className="button-ghost" type="button" onClick={close}>{t.close}</button>
            </div>
            <div id="command-results" className="command-results" role="listbox" aria-label={t.open}>
              {filtered.length === 0 ? <p className="command-empty" role="status">{t.empty}</p> : filtered.map((entry) => (
                <a key={`${entry.href}-${entry.label}`} id={`command-option-${filtered.indexOf(entry)}`} href={entry.href} role="option" aria-selected={filtered.indexOf(entry) === activeIndex} className={`command-result${filtered.indexOf(entry) === activeIndex ? " is-active" : ""}`} onMouseEnter={() => setActiveIndex(filtered.indexOf(entry))} onClick={(event) => activateEntry(entry, event)}>
                  <strong>{entry.label}</strong><span>{entry.hint}</span>
                </a>
              ))}
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}
