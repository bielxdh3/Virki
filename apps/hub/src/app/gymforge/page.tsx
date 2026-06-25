import { CSRF_FORM_FIELD_NAME, createCsrfToken } from "@bielos/auth/csrf";
import type { BielosLocale } from "@bielos/ui";
import { prisma } from "@bielos/database";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";
import { getLocale } from "../locale";
import { LanguageSelector } from "../language-selector";
import {
  changeGymForgeExerciseStatus,
  changeGymForgeParticipantStatus,
  createGymForgeAttendanceCheckIn,
  createGymForgeCompetition,
  createGymForgeExercise,
  createGymForgeParticipant,
  createGymForgeWorkout
} from "./actions";
import { getGymForgeAttendanceEffectiveDate } from "./dates";

export const dynamic = "force-dynamic";

const copy = {
  "pt-BR": {
    navLabel: "Navegação BielOS",
    privateHub: "Hub privado",
    primary: "Principal",
    returnHub: "Voltar ao hub",
    foundation: "Fundação",
    status: "Status",
    module: "Módulo",
    language: "Idioma",
    gated: "Fechado",
    mvpFoundation: "Fundação MVP",
    hero:
      "Fundação de competição de academia com acesso fechado para participantes convidados ou criados por admin. Tracking, check-ins, uploads, imports e cadastro público ainda não estão habilitados.",
    implementationStatus: "Status da implementação",
    schemaOnly: "Schema apenas",
    viewer: "Visualizador",
    linked: "Vinculado",
    notLinked: "Não vinculado",
    participant: "Participante",
    noParticipant: "Sem registro de participante GymForge",
    unavailable: "Indisponível",
    role: "Papel",
    attendance: "Presença",
    registry: "Registro",
    readOnly: "Somente leitura",
    participants: "Participantes",
    active: "Ativos",
    exercises: "Exercícios",
    competitions: "Competições",
    competition: "Competição",
    metadataFoundation: "Fundação de metadados",
    create: "Criar",
    adminOnly: "Admin apenas",
    name: "Nome",
    description: "Descrição",
    startsAt: "Início",
    endsAt: "Fim",
    scoringRule: "Regra de pontuação",
    createCompetition: "Criar competição",
    empty: "Vazio",
    noCompetitions: "Nenhuma competição ainda",
    ranking: "Ranking",
    attendanceAndStreaks: "Presença e sequências",
    group: "Grupo",
    activeOnly: "Ativos apenas",
    visits: "visitas",
    streak: "sequência",
    noRanking: "Nenhum participante ativo com presença ainda",
    latestCheckins: "Últimos check-ins",
    datesOnly: "Datas apenas",
    noCheckin: "Sem check-in",
    noLatestCheckins: "Sem últimos check-ins",
    todayCheckin: "Check-in de hoje",
    today: "Hoje",
    checkedIn: "Check-in feito",
    notCheckedIn: "Sem check-in",
    eligibility: "Elegibilidade",
    activeParticipant: "Participante ativo",
    requiresParticipant: "Requer vínculo com participante ACTIVE",
    streakCount: "Contagem de sequência",
    included: "Incluído",
    checkIn: "Check-in",
    onePerDay: "Um por dia",
    note: "Nota",
    alreadyCheckedIn: "Check-in já feito",
    createCheckin: "Criar check-in",
    workout: "Treino",
    entryFoundation: "Fundação de entrada",
    oneSet: "Uma série",
    exercise: "Exercício",
    selectExercise: "Selecionar exercício",
    setNumber: "Número da série",
    reps: "Repetições",
    load: "Carga",
    unit: "Unidade",
    workoutNote: "Nota do treino",
    setNote: "Nota da série",
    createWorkout: "Criar treino",
    latestWorkouts: "Últimos treinos",
    ownLogs: "Registros próprios",
    noSets: "Sem séries",
    noWorkouts: "Nenhum treino ainda",
    participantManagement: "Gestão de participantes",
    displayName: "Nome de exibição",
    createParticipant: "Criar participante",
    latest50: "Últimos 50",
    disable: "Desativar",
    archive: "Arquivar",
    noParticipants: "Nenhum participante GymForge ainda",
    exerciseCatalog: "Catálogo de exercícios",
    catalog: "Catálogo",
    exerciseName: "Nome do exercício",
    category: "Categoria",
    inactive: "Inativo",
    createExercise: "Criar exercício",
    uncategorized: "Sem categoria",
    deactivate: "Desativar",
    noExercises: "Nenhum exercício GymForge ainda",
    dataBoundaries: "Limites do modelo de dados implementado",
    foundationText: "Modelo de fundação existe. Mutações visíveis para usuários não estão habilitadas nesta fase.",
    noForms: "Sem formulários",
    internal: "Interno",
    safetyBoundary: "Limite de segurança",
    noPrivateIngestion: "Nenhuma ingestão de dados privados está habilitada",
    limitations:
      "GymForge permanece atrás da autenticação existente do hub. Prova por foto, edição de treinos, imports, exports e cadastro público permanecem bloqueados."
  },
  en: {
    navLabel: "BielOS navigation",
    privateHub: "Private Hub",
    primary: "Primary",
    returnHub: "Return to hub",
    foundation: "Foundation",
    status: "Status",
    module: "Module",
    language: "Language",
    gated: "Gated",
    mvpFoundation: "MVP Foundation",
    hero:
      "Gated gym competition foundation for invited or admin-created participants. Tracking, check-ins, uploads, imports, and public registration are not enabled yet.",
    implementationStatus: "Implementation status",
    schemaOnly: "Schema only",
    viewer: "Viewer",
    linked: "Linked",
    notLinked: "Not linked",
    participant: "Participant",
    noParticipant: "No GymForge participant record",
    unavailable: "Unavailable",
    role: "Role",
    attendance: "Attendance",
    registry: "Registry",
    readOnly: "Read only",
    participants: "Participants",
    active: "Active",
    exercises: "Exercises",
    competitions: "Competitions",
    competition: "Competition",
    metadataFoundation: "Metadata foundation",
    create: "Create",
    adminOnly: "Admin only",
    name: "Name",
    description: "Description",
    startsAt: "Starts at",
    endsAt: "Ends at",
    scoringRule: "Scoring rule",
    createCompetition: "Create competition",
    empty: "Empty",
    noCompetitions: "No competitions yet",
    ranking: "Ranking",
    attendanceAndStreaks: "Attendance and streaks",
    group: "Group",
    activeOnly: "Active only",
    visits: "visits",
    streak: "streak",
    noRanking: "No active participants with attendance yet",
    latestCheckins: "Latest check-ins",
    datesOnly: "Dates only",
    noCheckin: "No check-in",
    noLatestCheckins: "No latest check-ins",
    todayCheckin: "Today check-in",
    today: "Today",
    checkedIn: "Checked in",
    notCheckedIn: "Not checked in",
    eligibility: "Eligibility",
    activeParticipant: "Active participant",
    requiresParticipant: "Requires ACTIVE participant link",
    streakCount: "Streak count",
    included: "Included",
    checkIn: "Check in",
    onePerDay: "One per day",
    note: "Note",
    alreadyCheckedIn: "Already checked in",
    createCheckin: "Create check-in",
    workout: "Workout",
    entryFoundation: "Entry foundation",
    oneSet: "One set",
    exercise: "Exercise",
    selectExercise: "Select exercise",
    setNumber: "Set number",
    reps: "Reps",
    load: "Load",
    unit: "Unit",
    workoutNote: "Workout note",
    setNote: "Set note",
    createWorkout: "Create workout",
    latestWorkouts: "Latest workouts",
    ownLogs: "Own logs",
    noSets: "No sets",
    noWorkouts: "No workouts yet",
    participantManagement: "Participant management",
    displayName: "Display name",
    createParticipant: "Create participant",
    latest50: "Latest 50",
    disable: "Disable",
    archive: "Archive",
    noParticipants: "No GymForge participants yet",
    exerciseCatalog: "Exercise catalog",
    catalog: "Catalog",
    exerciseName: "Exercise name",
    category: "Category",
    inactive: "Inactive",
    createExercise: "Create exercise",
    uncategorized: "Uncategorized",
    deactivate: "Deactivate",
    noExercises: "No GymForge exercises yet",
    dataBoundaries: "Implemented data model boundaries",
    foundationText: "Foundation model exists. User-facing mutations are not enabled in this phase.",
    noForms: "No forms",
    internal: "Internal",
    safetyBoundary: "Safety boundary",
    noPrivateIngestion: "No private data ingestion is enabled",
    limitations:
      "GymForge remains behind existing hub auth. Photo proof, workout editing, imports, exports, and public registration remain blocked."
  }
} satisfies Record<BielosLocale, Record<string, string>>;

const foundationItems = {
  "pt-BR": [
    "Registros de participantes",
    "Catálogo de exercícios",
    "Schema de presença",
    "Notas de treino",
    "Séries de treino",
    "Metadados de competição"
  ],
  en: [
    "Participant records",
    "Exercise catalog",
    "Attendance schema",
    "Workout notes",
    "Workout sets",
    "Competition metadata"
  ]
} satisfies Record<BielosLocale, string[]>;

const formatCount = (count: number) => new Intl.NumberFormat("en-US").format(count);

function isHubAdmin(role: string): boolean {
  return role === "OWNER" || role === "ADMIN";
}

function formatDateKey(date: Date): string {
  return date.toISOString().slice(0, 10);
}

function addUtcDays(date: Date, days: number): Date {
  const nextDate = new Date(date);
  nextDate.setUTCDate(nextDate.getUTCDate() + days);
  return nextDate;
}

function calculateCurrentStreak(effectiveDates: Date[], today = getGymForgeAttendanceEffectiveDate()): number {
  const uniqueDates = new Set(effectiveDates.map(formatDateKey));
  const todayKey = formatDateKey(today);
  const yesterday = addUtcDays(today, -1);
  const yesterdayKey = formatDateKey(yesterday);

  if (!uniqueDates.has(todayKey) && !uniqueDates.has(yesterdayKey)) {
    return 0;
  }

  let streak = 0;
  let cursor = uniqueDates.has(todayKey) ? today : yesterday;

  while (uniqueDates.has(formatDateKey(cursor))) {
    streak += 1;
    cursor = addUtcDays(cursor, -1);
  }

  return streak;
}

function formatCompetitionDateRange(
  startsAt: Date | null,
  endsAt: Date | null,
  locale: BielosLocale
): string {
  if (startsAt && endsAt) {
    return locale === "pt-BR"
      ? `${formatDateKey(startsAt)} até ${formatDateKey(endsAt)}`
      : `${formatDateKey(startsAt)} to ${formatDateKey(endsAt)}`;
  }

  if (startsAt) {
    return locale === "pt-BR" ? `A partir de ${formatDateKey(startsAt)}` : `From ${formatDateKey(startsAt)}`;
  }

  if (endsAt) {
    return locale === "pt-BR" ? `Até ${formatDateKey(endsAt)}` : `Until ${formatDateKey(endsAt)}`;
  }

  return locale === "pt-BR" ? "Datas abertas" : "Open dates";
}

export default async function GymForgePage() {
  const requestHeaders = await headers();
  const accessResult = await validateHubCloudflareAccess(requestHeaders, "gymforge");

  if (!isCloudflareAccessAllowed(accessResult)) {
    forbidden();
  }

  const session = await getCurrentSession();

  if (!session) {
    redirect("/login");
  }

  const locale = await getLocale();
  const t = copy[locale];
  const [
    participantsCount,
    activeParticipantsCount,
    exerciseCatalogCount,
    competitionsCount,
    viewerParticipant,
    viewerAttendanceCount,
    viewerTodayAttendance,
    viewerWorkouts,
    rankingParticipants,
    participants,
    exercises,
    activeExercises,
    competitions
  ] = await Promise.all([
    prisma.gymForgeParticipant.count(),
    prisma.gymForgeParticipant.count({ where: { status: "ACTIVE" } }),
    prisma.gymForgeExercise.count({ where: { isActive: true } }),
    prisma.gymForgeCompetition.count(),
    prisma.gymForgeParticipant.findUnique({
      where: { userId: session.user.id },
      select: {
        id: true,
        displayName: true,
        status: true,
        role: true
      }
    }),
    prisma.gymForgeParticipant
      .findUnique({
        where: { userId: session.user.id },
        select: {
          _count: {
            select: {
              attendances: true
            }
          }
        }
      })
      .then((participant) => participant?._count.attendances ?? 0),
    prisma.gymForgeParticipant
      .findUnique({
        where: { userId: session.user.id },
        select: {
          attendances: {
            where: { effectiveDate: getGymForgeAttendanceEffectiveDate() },
            select: { id: true, countsForStreak: true },
            take: 1
          }
        }
      })
      .then((participant) => participant?.attendances[0] ?? null),
    prisma.gymForgeWorkout.findMany({
      where: {
        participant: {
          userId: session.user.id,
          status: "ACTIVE"
        }
      },
      orderBy: [{ workoutAt: "desc" }],
      take: 10,
      select: {
        id: true,
        workoutAt: true,
        sets: {
          select: {
            setNumber: true,
            reps: true,
            load: true,
            unit: true,
            exercise: { select: { name: true } }
          },
          orderBy: [{ setNumber: "asc" }]
        }
      }
    }),
    prisma.gymForgeParticipant.findMany({
      where: { status: "ACTIVE" },
      orderBy: [{ displayName: "asc" }],
      select: {
        displayName: true,
        attendances: {
          where: { countsForStreak: true },
          orderBy: [{ effectiveDate: "desc" }],
          select: {
            effectiveDate: true
          }
        }
      }
    }),
    prisma.gymForgeParticipant.findMany({
      orderBy: [{ createdAt: "desc" }],
      take: 50,
      select: {
        id: true,
        displayName: true,
        status: true,
        role: true,
        createdAt: true
      }
    }),
    prisma.gymForgeExercise.findMany({
      orderBy: [{ createdAt: "desc" }],
      take: 50,
      select: {
        id: true,
        name: true,
        category: true,
        isActive: true,
        archivedAt: true
      }
    }),
    prisma.gymForgeExercise.findMany({
      where: {
        isActive: true,
        archivedAt: null
      },
      orderBy: [{ name: "asc" }],
      select: {
        id: true,
        name: true
      }
    }),
    prisma.gymForgeCompetition.findMany({
      orderBy: [{ createdAt: "desc" }],
      take: 20,
      select: {
        id: true,
        name: true,
        status: true,
        startsAt: true,
        endsAt: true,
        scoringRule: true
      }
    })
  ]);

  const isAdmin = isHubAdmin(session.user.role);
  const canCheckIn = viewerParticipant?.status === "ACTIVE";
  const csrfToken = createCsrfToken();

  const metrics = [
    { label: t.participants, value: formatCount(participantsCount) },
    { label: t.active, value: formatCount(activeParticipantsCount) },
    { label: t.exercises, value: formatCount(exerciseCatalogCount) },
    { label: t.competitions, value: formatCount(competitionsCount) }
  ];
  const ranking = rankingParticipants
    .map((participant) => {
      const effectiveDates = participant.attendances.map((attendance) => attendance.effectiveDate);
      const latestCheckInDate = effectiveDates[0] ?? null;

      return {
        displayName: participant.displayName,
        totalAttendance: effectiveDates.length,
        currentStreak: calculateCurrentStreak(effectiveDates),
        latestCheckInDate
      };
    })
    .sort((left, right) => {
      if (right.totalAttendance !== left.totalAttendance) {
        return right.totalAttendance - left.totalAttendance;
      }

      if (right.currentStreak !== left.currentStreak) {
        return right.currentStreak - left.currentStreak;
      }

      const rightLatest = right.latestCheckInDate?.getTime() ?? 0;
      const leftLatest = left.latestCheckInDate?.getTime() ?? 0;

      if (rightLatest !== leftLatest) {
        return rightLatest - leftLatest;
      }

      return left.displayName.localeCompare(right.displayName);
    });

  return (
    <main className="hub-shell">
      <aside className="os-dock" aria-label={t.navLabel}>
        <div className="dock-identity">
          <img src="/hub-mark.svg" alt="" />
          <div>
            <strong>BielOS</strong>
            <span>{t.privateHub}</span>
          </div>
        </div>

        <nav className="dock-nav" aria-label={t.primary}>
          <a href="/" aria-label={t.returnHub}>
            <span aria-hidden="true">01</span>
            <strong>Hub</strong>
          </a>
          <a href="#foundation" aria-label={t.foundation}>
            <span aria-hidden="true">02</span>
            <strong>{t.foundation}</strong>
          </a>
          <a href="#status" aria-label={t.status}>
            <span aria-hidden="true">03</span>
            <strong>{t.status}</strong>
          </a>
        </nav>

        <div className="dock-footer">
          <span>{t.module}</span>
          <strong>{t.foundation}</strong>
        </div>
      </aside>

      <section className="hub-workspace">
        <header className="top-statusbar">
          <div className="statusbar-left">
            <span className="status-dot" aria-hidden="true" />
            <span>GymForge</span>
            <span>{t.gated}</span>
          </div>
          <div className="top-actions">
            <LanguageSelector locale={locale} label={t.language} returnTo="/gymforge" />
            <a className="icon-command" href="/">
              <span>{t.returnHub}</span>
            </a>
          </div>
        </header>

        <section className="identity-panel anchor-section" id="status" aria-label={t.status}>
          <div>
            <p className="eyebrow">GymForge</p>
            <h1>{t.mvpFoundation}</h1>
            <p>{t.hero}</p>
          </div>
          <div className="identity-meter" aria-label={t.implementationStatus}>
            <span>{t.status}</span>
            <strong>{t.schemaOnly}</strong>
          </div>
        </section>

        <section className="dashboard-grid" aria-label={t.status}>
          <article className="panel session-panel">
            <div className="panel-title">
              <span>{t.viewer}</span>
              <strong className="status-pill is-active">
                {viewerParticipant ? t.linked : t.notLinked}
              </strong>
            </div>
            <dl className="detail-list">
              <div>
                <dt>{t.participant}</dt>
                <dd>{viewerParticipant?.displayName ?? t.noParticipant}</dd>
              </div>
              <div>
                <dt>{t.status}</dt>
                <dd>{viewerParticipant?.status ?? t.unavailable}</dd>
              </div>
              <div>
                <dt>{t.role}</dt>
                <dd>{viewerParticipant?.role ?? t.unavailable}</dd>
              </div>
              <div>
                <dt>{t.attendance}</dt>
                <dd>{formatCount(viewerAttendanceCount)}</dd>
              </div>
            </dl>
          </article>

          <article className="panel deployment-panel">
            <div className="panel-title">
              <span>{t.registry}</span>
              <strong className="status-pill">{t.readOnly}</strong>
            </div>
            <div className="status-list">
              {metrics.map((metric) => (
                <div key={metric.label}>
                  <span>{metric.label}</span>
                  <strong>{metric.value}</strong>
                </div>
              ))}
            </div>
          </article>
        </section>

        <section className="module-window anchor-section" id="competitions" aria-label="GymForge competitions">
          <div className="window-titlebar">
            <div>
              <span>{t.competition}</span>
              <strong>{t.metadataFoundation}</strong>
            </div>
          </div>

          <div className="dashboard-grid">
            {isAdmin ? (
              <article className="panel">
                <div className="panel-title">
                  <span>{t.create}</span>
                  <strong className="status-pill">{t.adminOnly}</strong>
                </div>
                <form className="login-form" action={createGymForgeCompetition}>
                  <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                  <label>
                    {t.name}
                    <input name="name" minLength={2} maxLength={100} required />
                  </label>
                  <label>
                    {t.description}
                    <input name="description" maxLength={240} />
                  </label>
                  <label>
                    {t.status}
                    <select name="status" defaultValue="DRAFT">
                      <option value="DRAFT">Draft</option>
                      <option value="ACTIVE">Active</option>
                      <option value="ENDED">Ended</option>
                      <option value="ARCHIVED">Archived</option>
                    </select>
                  </label>
                  <label>
                    {t.startsAt}
                    <input name="startsAt" type="date" />
                  </label>
                  <label>
                    {t.endsAt}
                    <input name="endsAt" type="date" />
                  </label>
                  <label>
                    {t.scoringRule}
                    <input name="scoringRule" maxLength={120} required />
                  </label>
                  <button type="submit">{t.createCompetition}</button>
                </form>
              </article>
            ) : null}

            <article className="panel">
              <div className="panel-title">
                <span>{t.competitions}</span>
                <strong className="status-pill">{t.readOnly}</strong>
              </div>
              <div className="status-list">
                {competitions.map((competition) => (
                  <div key={competition.id}>
                    <span>{competition.name}</span>
                    <strong>
                      {competition.status} /{" "}
                      {formatCompetitionDateRange(competition.startsAt, competition.endsAt, locale)} /{" "}
                      {competition.scoringRule}
                    </strong>
                  </div>
                ))}
                {competitions.length === 0 ? (
                  <div>
                    <span>{t.empty}</span>
                    <strong>{t.noCompetitions}</strong>
                  </div>
                ) : null}
              </div>
            </article>
          </div>
        </section>

        <section className="module-window anchor-section" id="ranking" aria-label="GymForge ranking">
          <div className="window-titlebar">
            <div>
              <span>{t.ranking}</span>
              <strong>{t.attendanceAndStreaks}</strong>
            </div>
          </div>

          <div className="dashboard-grid">
            <article className="panel">
              <div className="panel-title">
                <span>{t.group}</span>
                <strong className="status-pill">{t.activeOnly}</strong>
              </div>
              <div className="status-list">
                {ranking.map((participant, index) => (
                  <div key={participant.displayName}>
                    <span>{index + 1}. {participant.displayName}</span>
                    <strong>
                      {formatCount(participant.totalAttendance)} {t.visits} /{" "}
                      {formatCount(participant.currentStreak)} {t.streak}
                    </strong>
                  </div>
                ))}
                {ranking.length === 0 ? (
                  <div>
                    <span>{t.empty}</span>
                    <strong>{t.noRanking}</strong>
                  </div>
                ) : null}
              </div>
            </article>

            <article className="panel">
              <div className="panel-title">
                <span>{t.latestCheckins}</span>
                <strong className="status-pill">{t.datesOnly}</strong>
              </div>
              <div className="status-list">
                {ranking.slice(0, 6).map((participant) => (
                  <div key={participant.displayName}>
                    <span>{participant.displayName}</span>
                    <strong>
                      {participant.latestCheckInDate
                        ? formatDateKey(participant.latestCheckInDate)
                        : t.noCheckin}
                    </strong>
                  </div>
                ))}
                {ranking.length === 0 ? (
                  <div>
                    <span>{t.empty}</span>
                    <strong>{t.noLatestCheckins}</strong>
                  </div>
                ) : null}
              </div>
            </article>
          </div>
        </section>

        <section className="module-window anchor-section" id="check-in" aria-label="GymForge check-in">
          <div className="window-titlebar">
            <div>
              <span>{t.attendance}</span>
              <strong>{t.todayCheckin}</strong>
            </div>
          </div>

          <div className="dashboard-grid">
            <article className="panel">
              <div className="panel-title">
                <span>{t.today}</span>
                <strong className="status-pill is-active">
                  {viewerTodayAttendance ? t.checkedIn : t.notCheckedIn}
                </strong>
              </div>
              <dl className="detail-list">
                <div>
                  <dt>{t.eligibility}</dt>
                  <dd>{canCheckIn ? t.activeParticipant : t.requiresParticipant}</dd>
                </div>
                <div>
                  <dt>{t.streakCount}</dt>
                  <dd>{viewerTodayAttendance?.countsForStreak ? t.included : t.unavailable}</dd>
                </div>
              </dl>
            </article>

            {canCheckIn ? (
              <article className="panel">
                <div className="panel-title">
                  <span>{t.checkIn}</span>
                  <strong className="status-pill">{t.onePerDay}</strong>
                </div>
                <form className="login-form" action={createGymForgeAttendanceCheckIn}>
                  <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                  <label>
                    {t.note}
                    <input name="note" maxLength={160} />
                  </label>
                  <button type="submit" disabled={Boolean(viewerTodayAttendance)}>
                    {viewerTodayAttendance ? t.alreadyCheckedIn : t.createCheckin}
                  </button>
                </form>
              </article>
            ) : null}
          </div>
        </section>

        <section className="module-window anchor-section" id="workouts" aria-label="GymForge workouts">
          <div className="window-titlebar">
            <div>
              <span>{t.workout}</span>
              <strong>{t.entryFoundation}</strong>
            </div>
          </div>

          <div className="dashboard-grid">
            {canCheckIn ? (
              <article className="panel">
                <div className="panel-title">
                  <span>{t.create}</span>
                  <strong className="status-pill">{t.oneSet}</strong>
                </div>
                <form className="login-form" action={createGymForgeWorkout}>
                  <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                  <label>
                    {t.exercise}
                    <select name="exerciseId" required>
                      <option value="">{t.selectExercise}</option>
                      {activeExercises.map((exercise) => (
                        <option key={exercise.id} value={exercise.id}>
                          {exercise.name}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    {t.setNumber}
                    <input name="setNumber" type="number" min={1} max={50} defaultValue={1} required />
                  </label>
                  <label>
                    {t.reps}
                    <input name="reps" type="number" min={1} max={500} required />
                  </label>
                  <label>
                    {t.load}
                    <input name="load" type="number" min={0} max={1000} step="0.01" />
                  </label>
                  <label>
                    {t.unit}
                    <select name="unit" defaultValue="KG">
                      <option value="KG">kg</option>
                      <option value="LB">lb</option>
                      <option value="BODYWEIGHT">bodyweight</option>
                      <option value="OTHER">other</option>
                    </select>
                  </label>
                  <label>
                    {t.workoutNote}
                    <input name="workoutNote" maxLength={240} />
                  </label>
                  <label>
                    {t.setNote}
                    <input name="setNote" maxLength={160} />
                  </label>
                  <button type="submit" disabled={activeExercises.length === 0}>
                    {t.createWorkout}
                  </button>
                </form>
              </article>
            ) : null}

            <article className="panel">
              <div className="panel-title">
                <span>{t.latestWorkouts}</span>
                <strong className="status-pill">{t.ownLogs}</strong>
              </div>
              <div className="status-list">
                {viewerWorkouts.map((workout) => (
                  <div key={workout.id}>
                    <span>{workout.workoutAt.toISOString().slice(0, 10)}</span>
                    <strong>
                      {workout.sets[0]
                        ? `${workout.sets[0].exercise.name}: ${workout.sets[0].reps} reps`
                        : t.noSets}
                    </strong>
                  </div>
                ))}
                {viewerWorkouts.length === 0 ? (
                  <div>
                    <span>{t.empty}</span>
                    <strong>{t.noWorkouts}</strong>
                  </div>
                ) : null}
              </div>
            </article>
          </div>
        </section>

        {isAdmin ? (
          <section className="module-window anchor-section" id="participants" aria-label="GymForge participants">
            <div className="window-titlebar">
              <div>
                <span>Admin</span>
                <strong>{t.participantManagement}</strong>
              </div>
            </div>

            <div className="dashboard-grid">
              <article className="panel">
                <div className="panel-title">
                  <span>{t.create}</span>
                  <strong className="status-pill">{t.adminOnly}</strong>
                </div>
                <form className="login-form" action={createGymForgeParticipant}>
                  <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                  <label>
                    {t.displayName}
                    <input name="displayName" minLength={2} maxLength={80} required />
                  </label>
                  <label>
                    {t.role}
                    <select name="role" defaultValue="PARTICIPANT">
                      <option value="PARTICIPANT">Participant</option>
                      <option value="ADMIN">Admin</option>
                    </select>
                  </label>
                  <label>
                    {t.status}
                    <select name="status" defaultValue="INVITED">
                      <option value="INVITED">Invited</option>
                      <option value="ACTIVE">Active</option>
                      <option value="DISABLED">Disabled</option>
                      <option value="ARCHIVED">Archived</option>
                    </select>
                  </label>
                  <button type="submit">{t.createParticipant}</button>
                </form>
              </article>

              <article className="panel">
                <div className="panel-title">
                  <span>{t.participants}</span>
                  <strong className="status-pill">{t.latest50}</strong>
                </div>
                <div className="status-list">
                  {participants.map((participant) => (
                    <div key={participant.id}>
                      <span>{participant.displayName}</span>
                      <strong>{participant.role} / {participant.status}</strong>
                      <form className="action-stack" action={changeGymForgeParticipantStatus}>
                        <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                        <input type="hidden" name="participantId" value={participant.id} />
                        <button type="submit" name="status" value="DISABLED">
                          {t.disable}
                        </button>
                        <button type="submit" name="status" value="ARCHIVED">
                          {t.archive}
                        </button>
                      </form>
                    </div>
                  ))}
                  {participants.length === 0 ? (
                    <div>
                      <span>{t.empty}</span>
                      <strong>{t.noParticipants}</strong>
                    </div>
                  ) : null}
                </div>
              </article>
            </div>
          </section>
        ) : null}

        {isAdmin ? (
          <section className="module-window anchor-section" id="exercises" aria-label="GymForge exercises">
            <div className="window-titlebar">
              <div>
                <span>Admin</span>
                <strong>{t.exerciseCatalog}</strong>
              </div>
            </div>

            <div className="dashboard-grid">
              <article className="panel">
                <div className="panel-title">
                  <span>{t.create}</span>
                  <strong className="status-pill">{t.catalog}</strong>
                </div>
                <form className="login-form" action={createGymForgeExercise}>
                  <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                  <label>
                    {t.exerciseName}
                    <input name="name" minLength={2} maxLength={100} required />
                  </label>
                  <label>
                    {t.category}
                    <input name="category" maxLength={80} />
                  </label>
                  <label>
                    {t.description}
                    <input name="description" maxLength={240} />
                  </label>
                  <label>
                    {t.status}
                    <select name="isActive" defaultValue="true">
                      <option value="true">{t.active}</option>
                      <option value="false">{t.inactive}</option>
                    </select>
                  </label>
                  <button type="submit">{t.createExercise}</button>
                </form>
              </article>

              <article className="panel">
                <div className="panel-title">
                  <span>{t.exercises}</span>
                  <strong className="status-pill">{t.latest50}</strong>
                </div>
                <div className="status-list">
                  {exercises.map((exercise) => (
                    <div key={exercise.id}>
                      <span>{exercise.name}</span>
                      <strong>
                        {exercise.category ?? t.uncategorized} /{" "}
                        {exercise.archivedAt ? "ARCHIVED" : exercise.isActive ? "ACTIVE" : "INACTIVE"}
                      </strong>
                      <form className="action-stack" action={changeGymForgeExerciseStatus}>
                        <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                        <input type="hidden" name="exerciseId" value={exercise.id} />
                        <button type="submit" name="action" value="deactivate">
                          {t.deactivate}
                        </button>
                        <button type="submit" name="action" value="archive">
                          {t.archive}
                        </button>
                      </form>
                    </div>
                  ))}
                  {exercises.length === 0 ? (
                    <div>
                      <span>{t.empty}</span>
                      <strong>{t.noExercises}</strong>
                    </div>
                  ) : null}
                </div>
              </article>
            </div>
          </section>
        ) : null}

        <section className="module-window anchor-section" id="foundation" aria-label="GymForge foundation">
          <div className="window-titlebar">
            <div>
              <span>{t.foundation}</span>
              <strong>{t.dataBoundaries}</strong>
            </div>
          </div>

          <div className="module-grid">
            {foundationItems[locale].map((item) => (
              <article className="module-card" key={item}>
                <div className="module-card-header">
                  <span className="module-icon">GF</span>
                  <span className="module-class">{t.internal}</span>
                </div>
                <h2>{item}</h2>
                <p>{t.foundationText}</p>
                <div className="module-tags">
                  <span className="is-reserved">{t.noForms}</span>
                  <span>{t.gated}</span>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="reserved-strip" aria-label="GymForge limitations">
          <div>
            <p className="eyebrow">{t.safetyBoundary}</p>
            <h2>{t.noPrivateIngestion}</h2>
            <p>{t.limitations}</p>
          </div>
        </section>
      </section>
    </main>
  );
}
