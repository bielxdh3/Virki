export type SensitivePageLifecycleTarget = Pick<Window, "addEventListener" | "removeEventListener">;
export type SensitivePageElement = { replaceChildren(): void };

export function clearSensitivePageElements(elements: Iterable<SensitivePageElement>): void {
  for (const element of elements) element.replaceChildren();
}

export function scrubSensitivePageSnapshot(clearState: () => void, elements: Iterable<SensitivePageElement>): void {
  clearState();
  clearSensitivePageElements(elements);
}

export function registerSensitivePageScrub(target: SensitivePageLifecycleTarget, scrub: () => void): () => void {
  const onPageHide = () => scrub();
  const onPageShow = (event: Event) => {
    if ("persisted" in event && event.persisted === true) scrub();
  };

  target.addEventListener("pagehide", onPageHide);
  target.addEventListener("pageshow", onPageShow);
  return () => {
    target.removeEventListener("pagehide", onPageHide);
    target.removeEventListener("pageshow", onPageShow);
  };
}

export function registerProtectedPageLifecycle(
  target: SensitivePageLifecycleTarget,
  scrub: () => void,
  reload: () => void,
  isHistoryTraversal: () => boolean = () => false,
): () => void {
  let revalidationRequested = false;
  const revalidate = () => {
    if (revalidationRequested) return;
    revalidationRequested = true;
    scrub();
    reload();
  };
  const onPageHide = () => scrub();
  const onPageShow = (event: Event) => {
    const restoredFromBackForwardCache = "persisted" in event && event.persisted === true;
    if (restoredFromBackForwardCache || isHistoryTraversal()) revalidate();
  };

  target.addEventListener("pagehide", onPageHide);
  target.addEventListener("pageshow", onPageShow);
  if (isHistoryTraversal()) revalidate();
  return () => {
    target.removeEventListener("pagehide", onPageHide);
    target.removeEventListener("pageshow", onPageShow);
  };
}
