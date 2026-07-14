import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import type { BielosLocale } from "@bielos/ui";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";

import { getCurrentSession } from "../../../lib/auth";
import {
  isCloudflareAccessAllowed,
  validateHubCloudflareAccess
} from "../../../lib/cloudflare-access";
import { LanguageSelector } from "../../language-selector";
import { getLocale } from "../../locale";
import { revokeAllOtherCoreSessions, revokeCoreSession } from "./actions";
import {
  type SafeAuditResource,
  type SafeAuditResult
} from "./audit-view";
import {
  CORE_AUDIT_DISPLAY_LIMIT,
  listCoreAuditActivity
} from "./audit-service";
import {
  CORE_SESSION_LIST_LIMIT,
  listCoreSessionsForPrincipal
} from "./session-service";

export const dynamic = "force-dynamic";

const copy = {
  "pt-BR": {
    privateHub: "Hub privado",
    navLabel: "Navegação de segurança BielOS Core",
    primary: "Principal",
    backHub: "Voltar ao hub",
    projects: "Projetos",
    security: "Segurança",
    protected: "Protegido",
    language: "Idioma",
    eyebrow: "BielOS Core",
    title: "Sessões pessoais",
    intro: "Revise e encerre somente as sessões vinculadas à sua própria conta.",
    activeSessions: "Sessões ativas",
    current: "Atual",
    other: "Outra sessão",
    created: "Criada",
    expires: "Expira",
    revoke: "Revogar sessão",
    currentNote: "A sessão atual só é encerrada pelo logout explícito.",
    empty: "Nenhuma sessão ativa foi encontrada.",
    limit: "Lista limitada às 100 sessões ativas mais recentes.",
    danger: "Encerrar outras sessões",
    dangerSummary: "Área de revogação",
    dangerCopy: "Revoga todas as outras sessões ativas desta conta e preserva a sessão atual.",
    dangerConfirm: "Confirmo a revogação de todas as outras sessões.",
    revokeAll: "Revogar todas as outras",
    noOthers: "Não há outras sessões ativas.",
    auditActivity: "Atividade de auditoria",
    ownerOnly: "Somente OWNER",
    newestAudit: "50 eventos mais recentes dentro da retenção ativa.",
    event: "Evento",
    result: "Resultado",
    resource: "Categoria",
    actor: "Ator",
    time: "Horário",
    actorUser: "Usuário",
    actorSystem: "Sistema",
    auditEmpty: "Nenhum evento de auditoria disponível.",
    resultSuccess: "Sucesso",
    resultFailure: "Falha",
    resultInfo: "Informação",
    resultOther: "Outro",
    resourceHub: "Hub",
    resourceSession: "Sessão",
    resourceProject: "Projeto",
    resourceProjectAccess: "Acesso de projeto",
    resourceApplication: "Aplicação",
    resourceSystem: "Sistema",
    resourceOther: "Outro"
  },
  en: {
    privateHub: "Private Hub",
    navLabel: "BielOS Core security navigation",
    primary: "Primary",
    backHub: "Back to hub",
    projects: "Projects",
    security: "Security",
    protected: "Protected",
    language: "Language",
    eyebrow: "BielOS Core",
    title: "Personal sessions",
    intro: "Review and revoke only sessions linked to your own account.",
    activeSessions: "Active sessions",
    current: "Current",
    other: "Other session",
    created: "Created",
    expires: "Expires",
    revoke: "Revoke session",
    currentNote: "The current session is ended only through explicit logout.",
    empty: "No active sessions were found.",
    limit: "List limited to the 100 most recent active sessions.",
    danger: "End other sessions",
    dangerSummary: "Revocation area",
    dangerCopy: "Revokes every other active session for this account and preserves the current session.",
    dangerConfirm: "I confirm revocation of every other session.",
    revokeAll: "Revoke all other sessions",
    noOthers: "There are no other active sessions.",
    auditActivity: "Audit activity",
    ownerOnly: "OWNER only",
    newestAudit: "50 newest events within active retention.",
    event: "Event",
    result: "Result",
    resource: "Category",
    actor: "Actor",
    time: "Time",
    actorUser: "User",
    actorSystem: "System",
    auditEmpty: "No audit activity is available.",
    resultSuccess: "Success",
    resultFailure: "Failure",
    resultInfo: "Information",
    resultOther: "Other",
    resourceHub: "Hub",
    resourceSession: "Session",
    resourceProject: "Project",
    resourceProjectAccess: "Project access",
    resourceApplication: "Application",
    resourceSystem: "System",
    resourceOther: "Other"
  }
} satisfies Record<BielosLocale, Record<string, string>>;

function formatSessionTime(value: Date, locale: BielosLocale): string {
  return new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(value);
}

function getAuditResultLabel(result: SafeAuditResult, locale: BielosLocale): string {
  const t = copy[locale];

  switch (result) {
    case "SUCCESS":
      return t.resultSuccess;
    case "FAILURE":
      return t.resultFailure;
    case "INFO":
      return t.resultInfo;
    default:
      return t.resultOther;
  }
}

function getAuditResourceLabel(resource: SafeAuditResource, locale: BielosLocale): string {
  const t = copy[locale];

  switch (resource) {
    case "hub":
      return t.resourceHub;
    case "session":
      return t.resourceSession;
    case "project":
      return t.resourceProject;
    case "project-access":
      return t.resourceProjectAccess;
    case "application":
      return t.resourceApplication;
    case "system":
      return t.resourceSystem;
    default:
      return t.resourceOther;
  }
}

export default async function CoreSecurityPage() {
  const requestHeaders = await headers();
  const accessResult = await validateHubCloudflareAccess(requestHeaders, "core-security");

  if (!isCloudflareAccessAllowed(accessResult)) {
    forbidden();
  }

  const session = await getCurrentSession();

  if (!session) {
    redirect("/login");
  }

  const locale = await getLocale();
  const t = copy[locale];
  const csrfToken = createCsrfToken();
  const now = new Date();
  const isOwner = session.user.role === "OWNER";
  const sessions = await listCoreSessionsForPrincipal(session.user, session.id, now);
  const auditLogs = isOwner ? await listCoreAuditActivity(session.user) : [];
  const otherSessionCount = sessions.filter((item) => !item.isCurrent).length;

  return (
    <main className="hub-shell core-security-shell">
      <aside className="os-dock" aria-label={t.navLabel}>
        <div className="dock-identity">
          <img src="/hub-mark.svg" alt="" width={64} height={64} />
          <div>
            <strong>BielOS</strong>
            <span>{t.privateHub}</span>
          </div>
        </div>

        <nav className="dock-nav" aria-label={t.primary}>
          <a href="/" aria-label={t.backHub}>
            <span aria-hidden="true">01</span>
            <strong>Hub</strong>
          </a>
          <a href="/core/projects" aria-label={t.projects}>
            <span aria-hidden="true">02</span>
            <strong>{t.projects}</strong>
          </a>
          <a href="#sessions" aria-label={t.security}>
            <span aria-hidden="true">03</span>
            <strong>{t.security}</strong>
          </a>
          {isOwner ? (
            <a href="#audit" aria-label={t.auditActivity}>
              <span aria-hidden="true">04</span>
              <strong>{t.auditActivity}</strong>
            </a>
          ) : null}
        </nav>

        <div className="dock-footer">
          <span>{t.activeSessions}</span>
          <strong>{sessions.length} / {CORE_SESSION_LIST_LIMIT}</strong>
        </div>
      </aside>

      <section className="hub-workspace core-security-workspace">
        <header className="top-statusbar">
          <div className="statusbar-left">
            <span className="status-dot" aria-hidden="true" />
            <span>BielOS Core</span>
            <span>{t.protected}</span>
          </div>
          <div className="top-actions">
            <a className="button-ghost core-back-link" href="/">{t.backHub}</a>
            <LanguageSelector locale={locale} label={t.language} returnTo="/core/security" />
          </div>
        </header>

        <header className="core-security-intro">
          <p className="eyebrow">{t.eyebrow}</p>
          <h1>{t.title}</h1>
          <p>{t.intro}</p>
        </header>

        <section className="core-session-section anchor-section" id="sessions" aria-labelledby="core-session-heading">
          <div className="section-heading core-session-heading">
            <div>
              <p className="eyebrow">{t.security}</p>
              <h2 id="core-session-heading">{t.activeSessions}</h2>
            </div>
            <span>{sessions.length} / {CORE_SESSION_LIST_LIMIT}</span>
          </div>

          {sessions.length === 0 ? (
            <div className="core-project-empty">
              <strong>{t.empty}</strong>
            </div>
          ) : (
            <div className="core-session-list">
              {sessions.map((item) => {
                const isCurrent = item.isCurrent;

                return (
                  <article className={`core-session-row${isCurrent ? " is-current" : ""}`} key={item.id}>
                    <div className="core-session-state">
                      <span className={`status-pill${isCurrent ? " is-active" : ""}`}>
                        {isCurrent ? t.current : t.other}
                      </span>
                    </div>
                    <dl>
                      <div>
                        <dt>{t.created}</dt>
                        <dd>{formatSessionTime(item.createdAt, locale)}</dd>
                      </div>
                      <div>
                        <dt>{t.expires}</dt>
                        <dd>{formatSessionTime(item.expiresAt, locale)}</dd>
                      </div>
                    </dl>
                    <div className="core-session-action">
                      {isCurrent ? (
                        <span>{t.currentNote}</span>
                      ) : (
                        <form action={revokeCoreSession}>
                          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                          <input type="hidden" name="sessionId" value={item.id} />
                          <button className="button-danger" type="submit">{t.revoke}</button>
                        </form>
                      )}
                    </div>
                  </article>
                );
              })}
            </div>
          )}

          <p className="core-project-limit-note">{t.limit}</p>

          <details className="admin-drawer core-session-danger">
            <summary>{t.dangerSummary}</summary>
            <div className="core-session-danger-body">
              <div>
                <strong>{t.danger}</strong>
                <p>{otherSessionCount > 0 ? t.dangerCopy : t.noOthers}</p>
              </div>
              {otherSessionCount > 0 ? (
                <form action={revokeAllOtherCoreSessions}>
                  <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                  <label className="checkbox-line">
                    <input type="checkbox" name="confirmAll" value="yes" required />
                    <span>{t.dangerConfirm}</span>
                  </label>
                  <button className="button-danger" type="submit">{t.revokeAll}</button>
                </form>
              ) : null}
            </div>
          </details>
        </section>

        {isOwner ? (
          <section className="core-audit-section anchor-section" id="audit" aria-labelledby="core-audit-heading">
            <div className="section-heading core-audit-heading">
              <div>
                <p className="eyebrow">{t.ownerOnly}</p>
                <h2 id="core-audit-heading">{t.auditActivity}</h2>
              </div>
              <span>{auditLogs.length} / {CORE_AUDIT_DISPLAY_LIMIT}</span>
            </div>

            {auditLogs.length === 0 ? (
              <div className="core-project-empty core-audit-empty">
                <strong>{t.auditEmpty}</strong>
              </div>
            ) : (
              <div className="core-audit-list">
                {auditLogs.map((item, index) => {
                  return (
                    <article
                      className="core-audit-row"
                      key={`${item.createdAt.toISOString()}-${index}`}
                    >
                      <div className="core-audit-event">
                        <span>{t.event}</span>
                        <code>{item.eventType}</code>
                      </div>
                      <dl>
                        <div>
                          <dt>{t.result}</dt>
                          <dd>
                            <span className={`core-audit-result is-${item.result.toLowerCase()}`}>
                              {getAuditResultLabel(item.result, locale)}
                            </span>
                          </dd>
                        </div>
                        <div>
                          <dt>{t.resource}</dt>
                          <dd>{getAuditResourceLabel(item.resource, locale)}</dd>
                        </div>
                        <div>
                          <dt>{t.actor}</dt>
                          <dd>{item.actorState === "user" ? t.actorUser : t.actorSystem}</dd>
                        </div>
                        <div>
                          <dt>{t.time}</dt>
                          <dd>{formatSessionTime(item.createdAt, locale)}</dd>
                        </div>
                      </dl>
                    </article>
                  );
                })}
              </div>
            )}

            <p className="core-project-limit-note">{t.newestAudit}</p>
          </section>
        ) : null}
      </section>
    </main>
  );
}
