import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { prisma } from "@bielos/database";
import { requireAdminPage } from "../../../lib/admin-page";
import { ConnectionForm } from "./connection-form";
import { ConnectionEditForm } from "./connection-edit-form";
import { deleteProjectConnectionAction, setProjectConnectionEnabledAction } from "../actions";
import { RotateSecretForm } from "./rotate-secret-form";
import { projectConnectionConfigurationRevision } from "../../../lib/connection-policy";

export const dynamic = "force-dynamic";

export default async function ConnectionsPage({ searchParams }: { searchParams: Promise<{ status?: string; error?: string }> }) {
  await requireAdminPage();
  const params = await searchParams;
  const [connections, csrf] = await Promise.all([
    prisma.projectConnection.findMany({ select: { id: true, name: true, slug: true, origin: true, launchUrl: true, redirectUris: true, enabled: true, _count: { select: { grants: true } } }, orderBy: [{ name: "asc" }, { id: "asc" }] }),
    Promise.resolve(createCsrfToken())
  ]);
  return <main className="admin-main" id="admin-content" tabIndex={-1}>
    <header className="page-header"><div><p className="eyebrow">Administração</p><h1>Conexões</h1><p>Clientes OIDC externos. BielOS não armazena nem hospeda suas experiências.</p></div></header>
    {params.status && <p className="form-success" role="status">Alteração concluída.</p>}
    {params.error && <p className="form-error" role="alert">A ação não foi concluída. Revise as conexões e a elevação de segurança.</p>}
    <section className="surface"><h2>Registrar projeto externo</h2><ConnectionForm csrf={csrf} /></section>
    <section className="surface"><h2>Projetos ({connections.length})</h2>
      {connections.length === 0 ? <p className="muted">Nenhuma conexão registrada.</p> : <div className="row-list">{connections.map((connection) => <article className="list-row connection-row" key={connection.id}>
        <div className="row-main"><strong>{connection.name} · {connection.enabled ? "Ativa" : "Desabilitada"}</strong><span>{connection.origin} · slug {connection.slug} · {connection._count.grants} concessões</span><span>URL de entrada: {connection.launchUrl ? <a href={connection.launchUrl}>{connection.launchUrl}</a> : "não configurada"}</span><details><summary>Redirect URIs allowlisted</summary><ul>{(Array.isArray(connection.redirectUris) ? connection.redirectUris : []).filter((uri): uri is string => typeof uri === "string").map((uri) => <li key={uri}><code>{uri}</code></li>)}</ul></details></div>
        <div className="form-actions">
          <ConnectionEditForm csrf={csrf} csrfFieldName={CSRF_FORM_FIELD_NAME} connection={{ id: connection.id, name: connection.name, slug: connection.slug, origin: connection.origin, launchUrl: connection.launchUrl, redirectUris: (Array.isArray(connection.redirectUris) ? connection.redirectUris : []).filter((uri): uri is string => typeof uri === "string"), configurationRevision: projectConnectionConfigurationRevision({ id: connection.id, name: connection.name, slug: connection.slug, origin: connection.origin, launchUrl: connection.launchUrl, redirectUris: (Array.isArray(connection.redirectUris) ? connection.redirectUris : []).filter((uri): uri is string => typeof uri === "string") }) }} />
          <form action={setProjectConnectionEnabledAction}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} /><input type="hidden" name="connectionId" value={connection.id} /><input type="hidden" name="enabled" value={connection.enabled ? "false" : "true"} /><button type="submit">{connection.enabled ? "Desabilitar" : "Habilitar"}</button></form>
          {connection.enabled && <RotateSecretForm csrf={csrf} connectionId={connection.id} />}
          <details><summary className="button-danger">Excluir conexão</summary><p>Excluir também remove as {connection._count.grants} concessões vinculadas e encerra artefatos OIDC pendentes. Os usuários deixarão de ver este projeto.</p><form action={deleteProjectConnectionAction}><input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} /><input type="hidden" name="connectionId" value={connection.id} /><label><input type="checkbox" name="confirmDelete" value="yes" required /> Entendo que a exclusão remove concessões</label><button className="button-danger" type="submit">Confirmar exclusão</button></form></details>
        </div>
      </article>)}</div>}
    </section>
  </main>;
}
