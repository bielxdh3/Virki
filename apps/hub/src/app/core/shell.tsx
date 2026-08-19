import React, { type ReactNode } from "react";
import type { BielosLocale } from "@bielos/ui";
import { getCoreNavigationItems, getCoreNavigationLabel } from "./navigation";

export type CoreShellVariant = "docked" | "standalone";

type CoreNavigationProps = {
  locale: BielosLocale;
  role: string;
  activePath?: string;
  layout: "docked" | "standalone";
};

type CoreShellProps = {
  children: ReactNode;
  locale: BielosLocale;
  role: string;
  variant: CoreShellVariant;
  activePath?: string;
  className?: string;
  footer?: ReactNode;
};

export function getCoreShellClassName(variant: CoreShellVariant, className = ""): string {
  return ["hub-shell", "core-shell", `hub-shell--${variant}`, className].filter(Boolean).join(" ");
}

function getPrivateHubLabel(locale: BielosLocale): string {
  return locale === "pt-BR" ? "Hub privado" : "Private Hub";
}

function CoreNavigation({ locale, role, activePath, layout }: CoreNavigationProps) {
  const items = getCoreNavigationItems(locale, role);

  return (
    <nav className={`dock-nav core-navigation core-navigation--${layout}`} aria-label={getCoreNavigationLabel(locale)}>
      {items.map((item, index) => (
        <a
          key={item.id}
          href={item.href}
          aria-current={item.kind === "route" && activePath === item.activePath ? "page" : undefined}
        >
          <span aria-hidden="true">{String(index + 1).padStart(2, "0")}</span>
          <strong>{item.label}</strong>
        </a>
      ))}
    </nav>
  );
}

export function CoreShell({ children, locale, role, variant, activePath, className, footer }: CoreShellProps) {
  const shellClassName = getCoreShellClassName(variant, className);

  return (
    <main className={shellClassName}>
      {variant === "docked" ? (
        <aside className="os-dock">
          <div className="dock-identity">
            <img src="/hub-mark.svg" alt="" width={64} height={64} />
            <div>
              <strong>BielOS</strong>
              <span>{getPrivateHubLabel(locale)}</span>
            </div>
          </div>
          <CoreNavigation locale={locale} role={role} activePath={activePath} layout="docked" />
          {footer ? <div className="dock-footer">{footer}</div> : null}
        </aside>
      ) : (
        <div className="core-standalone-navigation">
          <CoreNavigation locale={locale} role={role} activePath={activePath} layout="standalone" />
        </div>
      )}
      <section className="hub-workspace">{children}</section>
    </main>
  );
}
