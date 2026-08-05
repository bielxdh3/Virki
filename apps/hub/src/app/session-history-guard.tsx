"use client";

import { useEffect } from "react";

export function handlePageShow(
  event: Pick<PageTransitionEvent, "persisted">,
  reload: () => void
): void {
  if (event.persisted) reload();
}

export function SessionHistoryGuard() {
  useEffect(() => {
    const onPageShow = (event: PageTransitionEvent) => {
      handlePageShow(event, () => window.location.reload());
    };

    window.addEventListener("pageshow", onPageShow);
    return () => window.removeEventListener("pageshow", onPageShow);
  }, []);

  return null;
}
