"use client";

import { useEffect } from "react";
import { registerProtectedPageLifecycle } from "../lib/sensitive-page-lifecycle";

export function ProtectedPageLifecycle() {
  useEffect(() => registerProtectedPageLifecycle(
    window,
    () => {
      for (const element of document.querySelectorAll<HTMLElement>("[data-protected-page-content]")) {
        element.replaceChildren();
      }
    },
    () => window.location.reload(),
    () => {
      const userPortalRoute = window.location.pathname === "/" || window.location.pathname === "/account/security";
      const restoredFromHistory = (window.performance.getEntriesByType("navigation")[0] as PerformanceNavigationTiming | undefined)?.type === "back_forward";
      return userPortalRoute && restoredFromHistory;
    },
  ), []);

  return null;
}
