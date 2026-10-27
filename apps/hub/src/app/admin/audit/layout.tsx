import type { ReactNode } from "react";

// Keep the skip-link destination mounted while the audit route streams its
// loading state and then the final result. Replacing a focused <main> drops
// keyboard focus in Chromium.
export default function AuditLayout({ children }: { children: ReactNode }) {
  return <main className="admin-main" id="admin-content" tabIndex={-1}>{children}</main>;
}
