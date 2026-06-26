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
  archiveGymForgeCompetition,
  changeGymForgeExerciseStatus,
  changeGymForgeParticipantStatus,
  createGymForgeAttendanceCheckIn,
  createGymForgeCompetition,
  createGymForgeExercise,
  createGymForgeParticipant,
  createGymForgeWorkout,
  deleteGymForgeCompetition,
  updateGymForgeCompetition,
  updateGymForgeCompetitionAssignments
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
      "Fundação de competição de academia com acesso fechado. Check-ins, treinos, ranking, catálogo de exercícios, participantes e metadados de competição já estão ativos no hub privado.",
    implementationStatus: "Status da implementação",
    implementationSummary: "Fundação ativa",
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
    metadataFoundation: "Atribuição e pontuação",
    create: "Criar",
    adminOnly: "Admin apenas",
    name: "Nome",
    description: "Descrição",
    startsAt: "Início",
    endsAt: "Fim",
    dateRange: "Período",
    scoringRule: "Regra de pontuação",
    scoringRuleAttendance: "Presença total",
    scoringRuleCurrentStreak: "Sequência atual",
    scoringRuleLongestStreak: "Maior sequência",
    scoringRuleWeighted: "Presença + maior sequência",
    createCompetition: "Criar competição",
    lifecycle: "Ciclo de vida",
    updateCompetition: "Atualizar competição",
    archiveCompetition: "Arquivar competição",
    deleteCompetition: "Excluir competição",
    dangerZone: "Zona de risco",
    dangerZoneText: "Exclusão permanente só é permitida para competições não ACTIVE e sem participantes atribuídos.",
    confirmDelete: "Confirmo exclusão permanente",
    saveChanges: "Salvar alterações",
    manage: "Gerenciar",
    summary: "Resumo",
    assignment: "Atribuição",
    assignParticipants: "Atribuir participantes",
    updateAssignments: "Atualizar atribuições",
    assigned: "Atribuídos",
    automaticScoring: "Pontuação automática",
    score: "pontos",
    attendanceCount: "presenças",
    currentStreak: "sequência atual",
    longestStreak: "maior sequência",
    noScores: "Sem ranking automático disponível",
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
    foundationText: "Recurso de fundação ativo no hub privado, com controles de autenticação, CSRF e auditoria quando aplicável.",
    noForms: "Sem formulários",
    internal: "Interno",
    safetyBoundary: "Limite de segurança",
    noPrivateIngestion: "Recursos ainda bloqueados",
    limitations:
      "GymForge permanece atrás da autenticação existente do hub. Prova por foto, edição/exclusão de treinos, correção admin de presença, imports, exports, cadastro público, aceite de convite e feed social amplo permanecem bloqueados."
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
      "Gated gym competition foundation. Check-ins, workouts, ranking, exercise catalog, participants, and competition metadata are active inside the private hub.",
    implementationStatus: "Implementation status",
    implementationSummary: "Foundation active",
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
    metadataFoundation: "Assignment and scoring",
    create: "Create",
    adminOnly: "Admin only",
    name: "Name",
    description: "Description",
    startsAt: "Starts at",
    endsAt: "Ends at",
    dateRange: "Date range",
    scoringRule: "Scoring rule",
    scoringRuleAttendance: "Total attendance",
    scoringRuleCurrentStreak: "Current streak",
    scoringRuleLongestStreak: "Longest streak",
    scoringRuleWeighted: "Attendance + longest streak",
    createCompetition: "Create competition",
    lifecycle: "Lifecycle",
    updateCompetition: "Update competition",
    archiveCompetition: "Archive competition",
    deleteCompetition: "Delete competition",
    dangerZone: "Danger zone",
    dangerZoneText: "Permanent deletion is only allowed for non-ACTIVE competitions with no assigned participants.",
    confirmDelete: "I confirm permanent deletion",
    saveChanges: "Save changes",
    manage: "Manage",
    summary: "Summary",
    assignment: "Assignment",
    assignParticipants: "Assign participants",
    updateAssignments: "Update assignments",
    assigned: "Assigned",
    automaticScoring: "Automatic scoring",
    score: "points",
    attendanceCount: "attendance",
    currentStreak: "current streak",
    longestStreak: "longest streak",
    noScores: "No automatic ranking available",
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
    foundationText: "Foundation feature is active in the private hub, with auth, CSRF, and audit controls where applicable.",
    noForms: "No forms",
    internal: "Internal",
    safetyBoundary: "Safety boundary",
    noPrivateIngestion: "Still blocked",
    limitations:
      "GymForge remains behind existing hub auth. Photo proof, workout editing/deletion, admin attendance correction, imports, exports, public registration, invite acceptance, and broad social feed remain blocked."
  }
} satisfies Record<BielosLocale, Record<string, string>>;

const foundationItems = {
  "pt-BR": [
    "Registros de participantes",
    "Catálogo de exercícios",
    "Schema de presença",
    "Notas de treino",
    "Séries de treino",
    "Metadados de competição",
    "Atribuição e pontuação"
  ],
  en: [
    "Participant records",
    "Exercise catalog",
    "Attendance schema",
    "Workout notes",
    "Workout sets",
    "Competition metadata",
    "Assignment and scoring"
  ]
} satisfies Record<BielosLocale, string[]>;

const formatCount = (count: number) => new Intl.NumberFormat("en-US").format(count);

const COMPETITION_SCORING_RULES = [
  "ATTENDANCE_COUNT",
  "CURRENT_STREAK",
  "LONGEST_STREAK",
  "ATTENDANCE_PLUS_LONGEST_STREAK"
] as const;

type CompetitionScoringRule = (typeof COMPETITION_SCORING_RULES)[number];

const COMPETITION_SCORING_RULE_LABELS = {
  "pt-BR": {
    ATTENDANCE_COUNT: "Presença total",
    CURRENT_STREAK: "Sequência atual",
    LONGEST_STREAK: "Maior sequência",
    ATTENDANCE_PLUS_LONGEST_STREAK: "Presença + maior sequência"
  },
  en: {
    ATTENDANCE_COUNT: "Total attendance",
    CURRENT_STREAK: "Current streak",
    LONGEST_STREAK: "Longest streak",
    ATTENDANCE_PLUS_LONGEST_STREAK: "Attendance + longest streak"
  }
} satisfies Record<BielosLocale, Record<CompetitionScoringRule, string>>;

type CompetitionForScoring = {
  startsAt: Date | null;
  endsAt: Date | null;
  scoringRule: string;
  assignments: {
    participant: {
      displayName: string;
      attendances: {
        effectiveDate: Date;
      }[];
    };
  }[];
};

function isHubAdmin(role: string): boolean {
  return role === "OWNER" || role === "ADMIN";
}

function isCompetitionScoringRule(value: string): value is CompetitionScoringRule {
  return COMPETITION_SCORING_RULES.includes(value as CompetitionScoringRule);
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

function calculateLongestStreak(effectiveDates: Date[]): number {
  const uniqueDateKeys = Array.from(new Set(effectiveDates.map(formatDateKey))).sort();
  let longestStreak = 0;
  let currentStreak = 0;
  let previousDate: Date | null = null;

  for (const dateKey of uniqueDateKeys) {
    const date = new Date(`${dateKey}T00:00:00.000Z`);
    const expectedDate = previousDate ? addUtcDays(previousDate, 1) : null;
    currentStreak = expectedDate && formatDateKey(expectedDate) === dateKey ? currentStreak + 1 : 1;
    longestStreak = Math.max(longestStreak, currentStreak);
    previousDate = date;
  }

  return longestStreak;
}

function calculateCompetitionScores(competition: CompetitionForScoring) {
  if (!competition.startsAt || !competition.endsAt || !isCompetitionScoringRule(competition.scoringRule)) {
    return [];
  }

  const rangeStart = competition.startsAt.getTime();
  const rangeEnd = competition.endsAt.getTime();

  return competition.assignments
    .map((assignment) => {
      const effectiveDates = Array.from(
        new Map(
          assignment.participant.attendances
            .filter((attendance) => {
              const time = attendance.effectiveDate.getTime();
              return time >= rangeStart && time <= rangeEnd;
            })
            .map((attendance) => [formatDateKey(attendance.effectiveDate), attendance.effectiveDate])
        ).values()
      ).sort((left, right) => left.getTime() - right.getTime());
      const attendanceCount = effectiveDates.length;
      const currentStreak = calculateCurrentStreak(effectiveDates, competition.endsAt ?? undefined);
      const longestStreak = calculateLongestStreak(effectiveDates);
      const latestCheckInDate = effectiveDates.at(-1) ?? null;
      const score =
        competition.scoringRule === "ATTENDANCE_COUNT"
          ? attendanceCount
          : competition.scoringRule === "CURRENT_STREAK"
            ? currentStreak
            : competition.scoringRule === "LONGEST_STREAK"
              ? longestStreak
              : attendanceCount + longestStreak;

      return {
        displayName: assignment.participant.displayName,
        score,
        attendanceCount,
        currentStreak,
        longestStreak,
        latestCheckInDate
      };
    })
    .sort((left, right) => {
      if (right.score !== left.score) {
        return right.score - left.score;
      }

      if (right.attendanceCount !== left.attendanceCount) {
        return right.attendanceCount - left.attendanceCount;
      }

      if (right.longestStreak !== left.longestStreak) {
        return right.longestStreak - left.longestStreak;
      }

      const rightLatest = right.latestCheckInDate?.getTime() ?? 0;
      const leftLatest = left.latestCheckInDate?.getTime() ?? 0;

      if (rightLatest !== leftLatest) {
        return rightLatest - leftLatest;
      }

      return left.displayName.localeCompare(right.displayName);
    });
}

function _formatCompetitionDateRange(
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
    activeParticipantsForAssignment,
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
    prisma.gymForgeParticipant.findMany({
      where: { status: "ACTIVE" },
      orderBy: [{ displayName: "asc" }],
      select: {
        id: true,
        displayName: true
      }
    }),
    prisma.gymForgeCompetition.findMany({
      orderBy: [{ createdAt: "desc" }],
      take: 20,
      select: {
        id: true,
        name: true,
        description: true,
        status: true,
        startsAt: true,
        endsAt: true,
        archivedAt: true,
        scoringRule: true,
        _count: {
          select: {
            assignments: true
          }
        },
        assignments: {
          where: {
            participant: {
              status: "ACTIVE"
            }
          },
          orderBy: [{ assignedAt: "asc" }],
          select: {
            participantId: true,
            participant: {
              select: {
                displayName: true,
                status: true,
                attendances: {
                  where: { countsForStreak: true },
                  select: { effectiveDate: true },
                  orderBy: [{ effectiveDate: "asc" }]
                }
              }
            }
          }
        }
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
          <img src="/hub-mark.svg" alt="" width={64} height={64} />
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
            <strong>{t.implementationSummary}</strong>
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

        <section className="module-window anchor-section gymforge-competition-board" id="competitions" aria-label="GymForge competitions">
          <div className="window-titlebar">
            <div>
              <span>{t.competition}</span>
              <strong>{t.metadataFoundation}</strong>
            </div>
          </div>

          <div className="competition-toolbar">
            <div>
              <p className="eyebrow">{t.summary}</p>
              <h2>{t.competitions}</h2>
            </div>
            {isAdmin ? (
              <details className="admin-drawer">
                <summary>{t.createCompetition}</summary>
                <form className="compact-form" action={createGymForgeCompetition}>
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
                    <select name="status" defaultValue="DRAFT" aria-label={t.status}>
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
                    <select name="scoringRule" defaultValue="ATTENDANCE_COUNT" aria-label={t.scoringRule}>
                      <option value="ATTENDANCE_COUNT">{t.scoringRuleAttendance}</option>
                      <option value="CURRENT_STREAK">{t.scoringRuleCurrentStreak}</option>
                      <option value="LONGEST_STREAK">{t.scoringRuleLongestStreak}</option>
                      <option value="ATTENDANCE_PLUS_LONGEST_STREAK">{t.scoringRuleWeighted}</option>
                    </select>
                  </label>
                  <button className="button-primary" type="submit">{t.createCompetition}</button>
                </form>
              </details>
            ) : null}
          </div>

          <div className="competition-card-grid">
            {competitions.map((competition) => {
              const assignedParticipantIds = new Set(
                competition.assignments.map((assignment) => assignment.participantId)
              );
              const scores = calculateCompetitionScores(competition);
              const scoringRuleLabel = isCompetitionScoringRule(competition.scoringRule)
                ? COMPETITION_SCORING_RULE_LABELS[locale][competition.scoringRule]
                : competition.scoringRule;
              const dateRangeLabel = `${competition.startsAt ? formatDateKey(competition.startsAt) : t.unavailable} - ${
                competition.endsAt ? formatDateKey(competition.endsAt) : t.unavailable
              }`;

              return (
                <article className="competition-card" key={competition.id}>
                  <div className="competition-card-header">
                    <div>
                      <span className="status-pill">{competition.status}</span>
                      <h3>{competition.name}</h3>
                    </div>
                    <strong>{formatCount(competition._count.assignments)} {t.assigned}</strong>
                  </div>

                  <dl className="competition-meta">
                    <div>
                      <dt>{t.dateRange}</dt>
                      <dd>{dateRangeLabel}</dd>
                    </div>
                    <div>
                      <dt>{t.scoringRule}</dt>
                      <dd>{scoringRuleLabel}</dd>
                    </div>
                  </dl>

                  <section className="competition-scoreboard" aria-label={t.automaticScoring}>
                    <div className="panel-title">
                      <span>{t.automaticScoring}</span>
                      <strong className="status-pill">{t.readOnly}</strong>
                    </div>
                    <div className="status-list">
                      {scores.length === 0 ? (
                        <div>
                          <span>{t.empty}</span>
                          <strong>{t.noScores}</strong>
                        </div>
                      ) : (
                        scores.slice(0, 5).map((score, index) => (
                          <div key={`${competition.id}-${score.displayName}`}>
                            <span>{index + 1}. {score.displayName}</span>
                            <strong>
                              {formatCount(score.score)} {t.score} / {formatCount(score.attendanceCount)}{" "}
                              {t.attendanceCount} / {formatCount(score.longestStreak)} {t.longestStreak}
                            </strong>
                          </div>
                        ))
                      )}
                    </div>
                  </section>

                  {isAdmin ? (
                    <div className="admin-tool-grid">
                      <details className="admin-drawer">
                        <summary>{t.updateCompetition}</summary>
                        <form className="compact-form" action={updateGymForgeCompetition}>
                          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                          <input type="hidden" name="competitionId" value={competition.id} />
                          <label>
                            {t.name}
                            <input name="name" minLength={2} maxLength={100} defaultValue={competition.name} required />
                          </label>
                          <label>
                            {t.description}
                            <input name="description" maxLength={240} defaultValue={competition.description ?? ""} />
                          </label>
                          <label>
                            {t.status}
                            <select
                              name="status"
                              aria-label={t.status}
                              defaultValue={competition.status === "ARCHIVED" ? "DRAFT" : competition.status}
                            >
                              <option value="DRAFT">Draft</option>
                              <option value="ACTIVE">Active</option>
                              <option value="ENDED">Ended</option>
                            </select>
                          </label>
                          <label>
                            {t.startsAt}
                            <input
                              name="startsAt"
                              type="date"
                              defaultValue={competition.startsAt ? formatDateKey(competition.startsAt) : ""}
                            />
                          </label>
                          <label>
                            {t.endsAt}
                            <input
                              name="endsAt"
                              type="date"
                              defaultValue={competition.endsAt ? formatDateKey(competition.endsAt) : ""}
                            />
                          </label>
                          <label>
                            {t.scoringRule}
                            <select
                              name="scoringRule"
                              aria-label={t.scoringRule}
                              defaultValue={isCompetitionScoringRule(competition.scoringRule) ? competition.scoringRule : "ATTENDANCE_COUNT"}
                            >
                              <option value="ATTENDANCE_COUNT">{t.scoringRuleAttendance}</option>
                              <option value="CURRENT_STREAK">{t.scoringRuleCurrentStreak}</option>
                              <option value="LONGEST_STREAK">{t.scoringRuleLongestStreak}</option>
                              <option value="ATTENDANCE_PLUS_LONGEST_STREAK">{t.scoringRuleWeighted}</option>
                            </select>
                          </label>
                          <button className="button-primary" type="submit">{t.saveChanges}</button>
                        </form>
                      </details>

                      <details className="admin-drawer">
                        <summary>{t.assignment}</summary>
                        <form className="compact-form" action={updateGymForgeCompetitionAssignments}>
                          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                          <input type="hidden" name="competitionId" value={competition.id} />
                          <label>
                            {t.assignParticipants}
                            <select
                              name="participantId"
                              aria-label={t.assignParticipants}
                              multiple
                              size={Math.max(1, Math.min(activeParticipantsForAssignment.length, 6))}
                              defaultValue={Array.from(assignedParticipantIds)}
                            >
                              {activeParticipantsForAssignment.map((participant) => (
                                <option key={participant.id} value={participant.id}>
                                  {participant.displayName}
                                </option>
                              ))}
                            </select>
                          </label>
                          <button
                            className="button-secondary"
                            type="submit"
                            disabled={activeParticipantsForAssignment.length === 0}
                          >
                            {t.updateAssignments}
                          </button>
                        </form>
                      </details>

                      <details className="admin-drawer danger-zone">
                        <summary>{t.dangerZone}</summary>
                        <p>{t.dangerZoneText}</p>
                        <form className="action-stack" action={archiveGymForgeCompetition}>
                          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                          <input type="hidden" name="competitionId" value={competition.id} />
                          <button className="button-secondary" type="submit" disabled={competition.status === "ARCHIVED"}>
                            {t.archiveCompetition}
                          </button>
                        </form>
                        <form className="action-stack" action={deleteGymForgeCompetition}>
                          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                          <input type="hidden" name="competitionId" value={competition.id} />
                          <label className="checkbox-line">
                            <input name="confirmDelete" type="checkbox" value="true" />
                            {t.confirmDelete}
                          </label>
                          <button
                            className="button-danger"
                            type="submit"
                            disabled={competition.status === "ACTIVE" || competition._count.assignments > 0}
                          >
                            {t.deleteCompetition}
                          </button>
                        </form>
                      </details>
                    </div>
                  ) : null}
                </article>
              );
            })}
            {competitions.length === 0 ? (
              <article className="competition-card">
                <div className="competition-card-header">
                  <div>
                    <span className="status-pill">{t.empty}</span>
                    <h3>{t.noCompetitions}</h3>
                  </div>
                </div>
              </article>
            ) : null}
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
                    <select name="exerciseId" required aria-label={t.exercise}>
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
                    <select name="unit" defaultValue="KG" aria-label={t.unit}>
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

            <div className="admin-compact-section">
              <details className="admin-drawer admin-create-drawer">
                <summary>
                  <span>{t.createParticipant}</span>
                  <strong className="status-pill">{t.adminOnly}</strong>
                </summary>
                <form className="compact-form" action={createGymForgeParticipant}>
                  <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                  <label>
                    {t.displayName}
                    <input name="displayName" minLength={2} maxLength={80} required />
                  </label>
                  <label>
                    {t.role}
                    <select name="role" defaultValue="PARTICIPANT" aria-label={t.role}>
                      <option value="PARTICIPANT">Participant</option>
                      <option value="ADMIN">Admin</option>
                    </select>
                  </label>
                  <label>
                    {t.status}
                    <select name="status" defaultValue="INVITED" aria-label={t.status}>
                      <option value="INVITED">Invited</option>
                      <option value="ACTIVE">Active</option>
                      <option value="DISABLED">Disabled</option>
                      <option value="ARCHIVED">Archived</option>
                    </select>
                  </label>
                  <button className="button-primary" type="submit">{t.createParticipant}</button>
                </form>
              </details>

              <article className="compact-list-panel">
                <div className="panel-title">
                  <span>{t.participants}</span>
                  <strong className="status-pill">{t.latest50}</strong>
                </div>
                <div className="management-list">
                  {participants.map((participant) => (
                    <div className="management-row" key={participant.id}>
                      <div>
                        <span>{participant.displayName}</span>
                        <strong>{participant.role} / {participant.status}</strong>
                      </div>
                      <form className="row-actions" action={changeGymForgeParticipantStatus}>
                        <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                        <input type="hidden" name="participantId" value={participant.id} />
                        <button className="button-secondary" type="submit" name="status" value="DISABLED">
                          {t.disable}
                        </button>
                        <button className="button-danger" type="submit" name="status" value="ARCHIVED">
                          {t.archive}
                        </button>
                      </form>
                    </div>
                  ))}
                  {participants.length === 0 ? (
                    <div className="empty-row">
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

            <div className="admin-compact-section">
              <details className="admin-drawer admin-create-drawer">
                <summary>
                  <span>{t.createExercise}</span>
                  <strong className="status-pill">{t.catalog}</strong>
                </summary>
                <form className="compact-form" action={createGymForgeExercise}>
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
                    <select name="isActive" defaultValue="true" aria-label={t.status}>
                      <option value="true">{t.active}</option>
                      <option value="false">{t.inactive}</option>
                    </select>
                  </label>
                  <button className="button-primary" type="submit">{t.createExercise}</button>
                </form>
              </details>

              <article className="compact-list-panel">
                <div className="panel-title">
                  <span>{t.exercises}</span>
                  <strong className="status-pill">{t.latest50}</strong>
                </div>
                <div className="management-list">
                  {exercises.map((exercise) => (
                    <div className="management-row" key={exercise.id}>
                      <div>
                        <span>{exercise.name}</span>
                        <strong>
                          {exercise.category ?? t.uncategorized} /{" "}
                          {exercise.archivedAt ? "ARCHIVED" : exercise.isActive ? "ACTIVE" : "INACTIVE"}
                        </strong>
                      </div>
                      <form className="row-actions" action={changeGymForgeExerciseStatus}>
                        <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                        <input type="hidden" name="exerciseId" value={exercise.id} />
                        <button className="button-secondary" type="submit" name="action" value="deactivate">
                          {t.deactivate}
                        </button>
                        <button className="button-danger" type="submit" name="action" value="archive">
                          {t.archive}
                        </button>
                      </form>
                    </div>
                  ))}
                  {exercises.length === 0 ? (
                    <div className="empty-row">
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
