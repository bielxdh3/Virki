import { randomUUID } from "node:crypto";
import { CSRF_FORM_FIELD_NAME, createCsrfToken } from "@bielos/auth/csrf";
import type { BielosLocale } from "@bielos/ui";
import { prisma } from "@bielos/database";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";
import { getLocale } from "../locale";
import { LanguageSelector } from "../language-selector";
import { CoreShell } from "../core/shell";
import {
  archiveGymForgeCompetition,
  changeGymForgeExerciseStatus,
  changeGymForgeParticipantStatus,
  createGymForgeAdminAttendanceCorrection,
  createGymForgeAttendanceCheckIn,
  createGymForgeCompetition,
  createGymForgeCompetitionScoreCorrection,
  createGymForgeExercise,
  createGymForgeParticipant,
  createGymForgeWorkout,
  deleteGymForgeCompetition,
  deleteGymForgeWorkout,
  removeGymForgeAdminAttendanceCorrection,
  revokeGymForgeCompetitionScoreCorrection,
  updateGymForgeWorkout,
  updateGymForgeCompetition,
  updateGymForgeCompetitionAssignments
} from "./actions";
import { getGymForgeAttendanceEffectiveDate } from "./dates";
import {
  COMPETITION_SCORING_RULES,
  calculateCompetitionScores,
  calculateCurrentStreak,
  isCompetitionScoringRule,
  type CompetitionScoringRule
} from "./scoring";

export const dynamic = "force-dynamic";

type GymForgePageProps = {
  searchParams?: Promise<{
    error?: string;
  }>;
};

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
    actionError: "Não foi possível concluir a ação. Tente novamente.",
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
    draft: "Rascunho",
    activeState: "Ativa",
    ended: "Encerrada",
    archivedStatus: "Arquivada",
    invited: "Convidado",
    disabled: "Desativado",
    participantRole: "Participante",
    adminRole: "Administrador",
    checkInSource: "Check-in",
    correctionSourceLabel: "Correção administrativa",
    bodyweight: "Peso corporal",
    otherUnit: "Outra unidade",
    createCompetition: "Criar competição",
    lifecycle: "Ciclo de vida",
    updateCompetition: "Atualizar competição",
    archiveCompetition: "Arquivar competição",
    deleteCompetition: "Excluir competição",
    dangerZone: "Zona de risco",
    dangerZoneText:
      "Exclusão permanente só é permitida para competições não ativas, sem participantes atribuídos e sem histórico de correções.",
    correctionDeleteHint: "Exclusão bloqueada: esta competição possui histórico de correções.",
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
    finalScore: "Pontuação final",
    baseScore: "Pontuação base",
    activeAdjustment: "Ajuste ativo",
    attendanceCount: "presenças",
    currentStreak: "sequência atual",
    longestStreak: "maior sequência",
    noScores: "Sem ranking automático disponível",
    scoreCorrection: "Correções de pontuação",
    createScoreCorrection: "Criar correção",
    correctionParticipant: "Participante atribuído",
    selectParticipant: "Selecionar participante",
    pointsDelta: "Ajuste de pontos (-1000 a 1000, exceto 0)",
    correctionReason: "Motivo (opcional)",
    reason: "Motivo",
    recentCorrections: "Histórico recente",
    correctionSingular: "correção",
    correctionPlural: "correções",
    activeCorrection: "Ativa",
    revokedCorrection: "Revogada",
    revokeCorrection: "Revogar",
    noCorrections: "Nenhuma correção registrada",
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
    attendanceCorrection: "Correcao admin de presenca",
    createAttendanceCorrection: "Criar correcao de presenca",
    removeAttendanceCorrection: "Remover presenca",
    recentAttendance: "Presencas recentes",
    correctionDate: "Data da presenca",
    noRecentAttendance: "Sem presencas recentes",
    correctionSource: "Origem",
    todayCheckin: "Check-in de hoje",
    today: "Hoje",
    checkedIn: "Check-in feito",
    notCheckedIn: "Sem check-in",
    eligibility: "Elegibilidade",
    activeParticipant: "Participante ativo",
    requiresParticipant: "Requer vínculo com participante ativo",
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
    updateWorkout: "Editar treino",
    deleteWorkout: "Excluir treino",
    confirmWorkoutDelete: "Confirmo exclusao do treino",
    workoutDate: "Data do treino",
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
      "GymForge permanece atrás da autenticação existente do hub. Prova por foto, imports, exports, cadastro público, aceite de convite e feed social amplo permanecem bloqueados."
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
    actionError: "The action could not be completed. Try again.",
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
    draft: "Draft",
    activeState: "Active",
    ended: "Ended",
    archivedStatus: "Archived",
    invited: "Invited",
    disabled: "Disabled",
    participantRole: "Participant",
    adminRole: "Administrator",
    checkInSource: "Check-in",
    correctionSourceLabel: "Admin correction",
    bodyweight: "Bodyweight",
    otherUnit: "Other unit",
    createCompetition: "Create competition",
    lifecycle: "Lifecycle",
    updateCompetition: "Update competition",
    archiveCompetition: "Archive competition",
    deleteCompetition: "Delete competition",
    dangerZone: "Danger zone",
    dangerZoneText:
      "Permanent deletion is only allowed for competitions that are not active, with no assigned participants and no correction history.",
    correctionDeleteHint: "Deletion blocked: this competition has correction history.",
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
    finalScore: "Final score",
    baseScore: "Base score",
    activeAdjustment: "Active adjustment",
    attendanceCount: "attendance",
    currentStreak: "current streak",
    longestStreak: "longest streak",
    noScores: "No automatic ranking available",
    scoreCorrection: "Score corrections",
    createScoreCorrection: "Create correction",
    correctionParticipant: "Assigned participant",
    selectParticipant: "Select participant",
    pointsDelta: "Point adjustment (-1000 to 1000, excluding 0)",
    correctionReason: "Reason (optional)",
    reason: "Reason",
    recentCorrections: "Recent history",
    correctionSingular: "correction",
    correctionPlural: "corrections",
    activeCorrection: "Active",
    revokedCorrection: "Revoked",
    revokeCorrection: "Revoke",
    noCorrections: "No corrections recorded",
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
    attendanceCorrection: "Admin attendance correction",
    createAttendanceCorrection: "Create attendance correction",
    removeAttendanceCorrection: "Remove attendance",
    recentAttendance: "Recent attendance",
    correctionDate: "Attendance date",
    noRecentAttendance: "No recent attendance",
    correctionSource: "Source",
    todayCheckin: "Today check-in",
    today: "Today",
    checkedIn: "Checked in",
    notCheckedIn: "Not checked in",
    eligibility: "Eligibility",
    activeParticipant: "Active participant",
    requiresParticipant: "Requires an active participant link",
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
    updateWorkout: "Edit workout",
    deleteWorkout: "Delete workout",
    confirmWorkoutDelete: "I confirm workout deletion",
    workoutDate: "Workout date",
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
      "GymForge remains behind existing hub auth. Photo proof, imports, exports, public registration, invite acceptance, and broad social feed remain blocked."
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
const formatSignedCount = (count: number) =>
  new Intl.NumberFormat("en-US", { signDisplay: "always" }).format(count);

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

function competitionStatusLabel(value: string, locale: BielosLocale): string {
  const t = copy[locale];
  return ({ DRAFT: t.draft, ACTIVE: t.activeState, ENDED: t.ended, ARCHIVED: t.archivedStatus } as Record<string, string>)[value] ?? t.unavailable;
}

function participantStatusLabel(value: string, locale: BielosLocale): string {
  const t = copy[locale];
  return ({ INVITED: t.invited, ACTIVE: t.activeState, DISABLED: t.disabled, ARCHIVED: t.archivedStatus } as Record<string, string>)[value] ?? t.unavailable;
}

function participantRoleLabel(value: string, locale: BielosLocale): string {
  const t = copy[locale];
  return ({ PARTICIPANT: t.participantRole, ADMIN: t.adminRole } as Record<string, string>)[value] ?? t.unavailable;
}

function attendanceSourceLabel(value: string | null, locale: BielosLocale): string {
  const t = copy[locale];
  return value === "ADMIN_CORRECTION" ? t.correctionSourceLabel : value === "CHECK_IN" || !value ? t.checkInSource : t.correctionSourceLabel;
}

function isHubAdmin(role: string): boolean {
  return role === "OWNER" || role === "ADMIN";
}

function formatDateKey(date: Date): string {
  return date.toISOString().slice(0, 10);
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

export default async function GymForgePage({ searchParams }: GymForgePageProps) {
  const requestHeaders = await headers();
  const accessResult = await validateHubCloudflareAccess(requestHeaders, "gymforge");

  if (!isCloudflareAccessAllowed(accessResult)) {
    forbidden();
  }

  const session = await getCurrentSession();

  if (!session) {
    redirect("/login");
  }

  const params = await searchParams;
  const locale = await getLocale();
  const t = copy[locale];
  const isAdmin = isHubAdmin(session.user.role);
  const viewerParticipant = await prisma.gymForgeParticipant.findUnique({
    where: { userId: session.user.id },
    select: {
      id: true,
      displayName: true,
      status: true,
      role: true
    }
  });

  if (!isAdmin && viewerParticipant?.status !== "ACTIVE") {
    forbidden();
  }

  const todayAnchor = getGymForgeAttendanceEffectiveDate();
  const [
    participantsCount,
    activeParticipantsCount,
    exerciseCatalogCount,
    competitionsCount,
    viewerAttendanceCount,
    viewerTodayAttendance,
    viewerWorkouts,
    rankingParticipants,
    participants,
    exercises,
    activeExercises,
    activeParticipantsForAssignment,
    competitions,
    recentAttendances
  ] = await Promise.all([
    prisma.gymForgeParticipant.count(),
    prisma.gymForgeParticipant.count({ where: { status: "ACTIVE" } }),
    prisma.gymForgeExercise.count({ where: { isActive: true } }),
    prisma.gymForgeCompetition.count(),
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
            where: { effectiveDate: todayAnchor },
            select: { id: true, countsForStreak: true },
            take: 1
          }
        }
      })
      .then((participant) => participant?.attendances[0] ?? null),
    prisma.gymForgeWorkout.findMany({
      where: isAdmin
        ? {}
        : {
            participant: {
              userId: session.user.id,
              status: "ACTIVE"
            }
          },
      orderBy: [{ workoutAt: "desc" }],
      take: isAdmin ? 30 : 10,
      select: {
        id: true,
        workoutAt: true,
        note: true,
        participant: {
          select: {
            displayName: true,
            status: true
          }
        },
        sets: {
          select: {
            id: true,
            setNumber: true,
            reps: true,
            load: true,
            unit: true,
            note: true,
            exerciseId: true,
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
            assignments: true,
            scoreCorrections: true
          }
        },
        assignments: {
          orderBy: [{ assignedAt: "asc" }],
          select: {
            participantId: true,
            participant: {
              select: {
                id: true,
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
    }),
    isAdmin
      ? prisma.gymForgeAttendance.findMany({
          orderBy: [{ effectiveDate: "desc" }, { checkedInAt: "desc" }],
          take: 30,
          select: {
            id: true,
            effectiveDate: true,
            source: true,
            countsForStreak: true,
            participant: {
              select: {
                displayName: true,
                status: true
              }
            }
          }
        })
      : Promise.resolve([])
  ]);

  const competitionIds = competitions.map((competition) => competition.id);
  const [activeCorrectionTotals, recentScoreCorrections] = await Promise.all([
    prisma.gymForgeCompetitionScoreCorrection.groupBy({
      by: ["competitionId", "participantId"],
      where: {
        competitionId: { in: competitionIds },
        revokedAt: null
      },
      _sum: { pointsDelta: true }
    }),
    isAdmin
      ? prisma.gymForgeCompetitionScoreCorrection.findMany({
          where: { competitionId: { in: competitionIds } },
          orderBy: [{ createdAt: "desc" }],
          take: 200,
          select: {
            id: true,
            competitionId: true,
            participantId: true,
            pointsDelta: true,
            reason: true,
            createdAt: true,
            revokedAt: true,
            participant: {
              select: { displayName: true }
            }
          }
        })
      : Promise.resolve([])
  ]);
  const activeCorrectionsByCompetition = new Map<
    string,
    { participantId: string; pointsDelta: number; revokedAt: null }[]
  >();
  const correctionHistoryByCompetition = new Map<string, typeof recentScoreCorrections>();

  for (const total of activeCorrectionTotals) {
    const entries = activeCorrectionsByCompetition.get(total.competitionId) ?? [];
    entries.push({
      participantId: total.participantId,
      pointsDelta: total._sum.pointsDelta ?? 0,
      revokedAt: null
    });
    activeCorrectionsByCompetition.set(total.competitionId, entries);
  }

  for (const correction of recentScoreCorrections) {
    const entries = correctionHistoryByCompetition.get(correction.competitionId) ?? [];
    entries.push(correction);
    correctionHistoryByCompetition.set(correction.competitionId, entries);
  }

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
        currentStreak: calculateCurrentStreak(effectiveDates, todayAnchor),
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
    <CoreShell
      variant="docked"
      locale={locale}
      role={session.user.role}
      className="gymforge-shell"
      footer={<><span>{t.module}</span><strong>{t.foundation}</strong></>}
    >
        <header className="top-statusbar">
          <div className="statusbar-left">
            <span className="status-dot" aria-hidden="true" />
            <span>GymForge</span>
            <span>{t.gated}</span>
          </div>
          <div className="top-actions">
            <LanguageSelector locale={locale} label={t.language} returnTo="/gymforge" />
            <a className="icon-command button-ghost" href="/">
              <span>{t.returnHub}</span>
            </a>
          </div>
        </header>

        {params?.error ? (
          <p className="gymforge-module-alert" role="alert">
            {t.actionError}
          </p>
        ) : null}

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
                <dd>{viewerParticipant ? participantStatusLabel(viewerParticipant.status, locale) : t.unavailable}</dd>
              </div>
              <div>
                <dt>{t.role}</dt>
                <dd>{viewerParticipant ? participantRoleLabel(viewerParticipant.role, locale) : t.unavailable}</dd>
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
                      <option value="DRAFT">{t.draft}</option>
                      <option value="ACTIVE">{t.activeState}</option>
                      <option value="ENDED">{t.ended}</option>
                      <option value="ARCHIVED">{t.archivedStatus}</option>
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
                      {COMPETITION_SCORING_RULES.map((rule) => (
                        <option key={rule} value={rule}>
                          {COMPETITION_SCORING_RULE_LABELS[locale][rule]}
                        </option>
                      ))}
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
              const correctionParticipants = competition.assignments.filter(
                (assignment) => assignment.participant.status === "ACTIVE"
              );
              const canCreateScoreCorrection =
                isAdmin && ["ACTIVE", "ENDED"].includes(competition.status);
              const canRevokeScoreCorrection =
                isAdmin && ["ACTIVE", "ENDED", "ARCHIVED"].includes(competition.status);
              const correctionRequestKey = canCreateScoreCorrection ? randomUUID() : null;
              const correctionHistory = correctionHistoryByCompetition.get(competition.id) ?? [];
              const scores = calculateCompetitionScores({
                ...competition,
                scoreCorrections: activeCorrectionsByCompetition.get(competition.id) ?? []
              });
              const scoringRuleLabel = isCompetitionScoringRule(competition.scoringRule)
                ? COMPETITION_SCORING_RULE_LABELS[locale][competition.scoringRule]
                : t.unavailable;
              const dateRangeLabel = `${competition.startsAt ? formatDateKey(competition.startsAt) : t.unavailable} - ${
                competition.endsAt ? formatDateKey(competition.endsAt) : t.unavailable
              }`;

              return (
                <article className="competition-card" key={competition.id}>
                  <div className="competition-card-header">
                    <div className="competition-titleline">
                      <span className={`status-pill status-${competition.status.toLowerCase()}`}>{competitionStatusLabel(competition.status, locale)}</span>
                      <h3>{competition.name}</h3>
                    </div>
                    <div className="competition-count">
                      <strong>{formatCount(competition._count.assignments)}</strong>
                      <span>{t.assigned}</span>
                    </div>
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
                    <div className="scoreboard-header">
                      <strong>{t.automaticScoring}</strong>
                      <strong className="status-pill">{t.readOnly}</strong>
                    </div>
                    <div className="score-list">
                      {scores.length === 0 ? (
                        <div className="score-row is-empty">
                          <strong>{t.noScores}</strong>
                          <span>{t.empty}</span>
                        </div>
                      ) : (
                        scores.slice(0, 5).map((score, index) => (
                          <div className="score-row" key={score.participantId}>
                            <strong>{index + 1}. {score.displayName}</strong>
                            <div className="score-breakdown">
                              <span className="score-breakdown-primary">
                                {t.finalScore}: <strong>{formatCount(score.finalScore)}</strong> {t.score}
                              </span>
                              <span>{t.baseScore}: {formatCount(score.baseScore)}</span>
                              <span>{t.activeAdjustment}: {formatSignedCount(score.activeAdjustment)}</span>
                              <span>{t.attendanceCount}: {formatCount(score.attendanceCount)}</span>
                              <span>{t.longestStreak}: {formatCount(score.longestStreak)}</span>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </section>

                  {isAdmin ? (
                    <div className="competition-actions">
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
                              <option value="DRAFT">{t.draft}</option>
                              <option value="ACTIVE">{t.activeState}</option>
                              <option value="ENDED">{t.ended}</option>
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
                              {COMPETITION_SCORING_RULES.map((rule) => (
                                <option key={rule} value={rule}>
                                  {COMPETITION_SCORING_RULE_LABELS[locale][rule]}
                                </option>
                              ))}
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

                      <details className="admin-drawer score-correction-drawer">
                        <summary>
                          {t.scoreCorrection} ({formatCount(competition._count.scoreCorrections)})
                        </summary>
                        <div className="score-correction-content">
                          {canCreateScoreCorrection && correctionRequestKey ? (
                            <form
                              className="compact-form score-correction-form"
                              action={createGymForgeCompetitionScoreCorrection}
                            >
                              <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                              <input type="hidden" name="competitionId" value={competition.id} />
                              <input type="hidden" name="requestKey" value={correctionRequestKey} />
                              <label>
                                {t.correctionParticipant}
                                <select
                                  name="participantId"
                                  defaultValue=""
                                  disabled={correctionParticipants.length === 0}
                                  required
                                >
                                  <option value="" disabled>
                                    {t.selectParticipant}
                                  </option>
                                  {correctionParticipants.map((assignment) => (
                                    <option
                                      key={assignment.participantId}
                                      value={assignment.participantId}
                                    >
                                      {assignment.participant.displayName}
                                    </option>
                                  ))}
                                </select>
                              </label>
                              <label>
                                {t.pointsDelta}
                                <input
                                  name="pointsDelta"
                                  type="number"
                                  min={-1000}
                                  max={1000}
                                  step={1}
                                  required
                                />
                              </label>
                              <label className="score-correction-reason">
                                {t.correctionReason}
                                <input name="reason" maxLength={240} />
                              </label>
                              <button
                                className="button-primary"
                                type="submit"
                                disabled={correctionParticipants.length === 0}
                              >
                                {t.createScoreCorrection}
                              </button>
                            </form>
                          ) : null}

                          <section className="correction-history" aria-label={t.recentCorrections}>
                            <div className="correction-history-header">
                              <strong>{t.recentCorrections}</strong>
                              <span>
                                {formatCount(competition._count.scoreCorrections)}{" "}
                                {competition._count.scoreCorrections === 1
                                  ? t.correctionSingular
                                  : t.correctionPlural}
                              </span>
                            </div>
                            <div className="correction-list">
                              {correctionHistory.map((correction) => (
                                <div className="correction-row" key={correction.id}>
                                  <div className="correction-row-copy">
                                    <div className="correction-row-main">
                                      <strong>{correction.participant.displayName}</strong>
                                      <span
                                        className={`status-pill ${
                                          correction.revokedAt ? "status-archived" : "is-active"
                                        }`}
                                      >
                                        {correction.revokedAt
                                          ? t.revokedCorrection
                                          : t.activeCorrection}
                                      </span>
                                    </div>
                                    <div className="correction-row-meta">
                                      <strong>
                                        {formatSignedCount(correction.pointsDelta)} {t.score}
                                      </strong>
                                      <time dateTime={correction.createdAt.toISOString()}>
                                        {formatDateKey(correction.createdAt)}
                                      </time>
                                    </div>
                                    {correction.reason ? (
                                      <p className="correction-reason">
                                        <span>{t.reason}:</span> {correction.reason}
                                      </p>
                                    ) : null}
                                  </div>
                                  {!correction.revokedAt && canRevokeScoreCorrection ? (
                                    <form
                                      className="row-actions correction-revoke-form"
                                      action={revokeGymForgeCompetitionScoreCorrection}
                                    >
                                      <input
                                        type="hidden"
                                        name={CSRF_FORM_FIELD_NAME}
                                        value={csrfToken}
                                      />
                                      <input
                                        type="hidden"
                                        name="correctionId"
                                        value={correction.id}
                                      />
                                      <button className="button-ghost" type="submit">
                                        {t.revokeCorrection}
                                      </button>
                                    </form>
                                  ) : null}
                                </div>
                              ))}
                              {correctionHistory.length === 0 ? (
                                <p className="correction-empty">{t.noCorrections}</p>
                              ) : null}
                            </div>
                          </section>
                        </div>
                      </details>

                      <details className="admin-drawer danger-zone">
                        <summary>{t.dangerZone}</summary>
                        <p>{t.dangerZoneText}</p>
                        {competition._count.scoreCorrections > 0 ? (
                          <p><strong>{t.correctionDeleteHint}</strong></p>
                        ) : null}
                        <form className="action-stack button-row" action={archiveGymForgeCompetition}>
                          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                          <input type="hidden" name="competitionId" value={competition.id} />
                          <button className="button-secondary" type="submit" disabled={competition.status === "ARCHIVED"}>
                            {t.archiveCompetition}
                          </button>
                        </form>
                        <form className="action-stack button-row" action={deleteGymForgeCompetition}>
                          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                          <input type="hidden" name="competitionId" value={competition.id} />
                          <label className="checkbox-line">
                            <input name="confirmDelete" type="checkbox" value="true" />
                            {t.confirmDelete}
                          </label>
                          <button
                            className="button-danger"
                            type="submit"
                            disabled={
                              competition.status === "ACTIVE" ||
                              competition._count.assignments > 0 ||
                              competition._count.scoreCorrections > 0
                            }
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
                  <button className="button-primary" type="submit" disabled={Boolean(viewerTodayAttendance)}>
                    {viewerTodayAttendance ? t.alreadyCheckedIn : t.createCheckin}
                  </button>
                </form>
              </article>
            ) : null}
          </div>

          {isAdmin ? (
            <div className="management-strip">
              <details className="admin-drawer create-strip-drawer">
                <summary>
                  <span>{t.attendanceCorrection}</span>
                  <strong className="status-pill">{t.adminOnly}</strong>
                </summary>
                <form className="compact-form" action={createGymForgeAdminAttendanceCorrection}>
                  <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                  <label>
                    {t.participant}
                    <select name="participantId" required aria-label={t.participant}>
                      <option value="">{t.participant}</option>
                      {activeParticipantsForAssignment.map((participant) => (
                        <option key={participant.id} value={participant.id}>
                          {participant.displayName}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    {t.correctionDate}
                    <input name="effectiveDate" type="date" required />
                  </label>
                  <button
                    className="button-primary"
                    type="submit"
                    disabled={activeParticipantsForAssignment.length === 0}
                  >
                    {t.createAttendanceCorrection}
                  </button>
                </form>
              </details>

              <div className="management-list compact-management-list" aria-label={t.recentAttendance}>
                {recentAttendances.map((attendance) => (
                  <div className="management-row" key={attendance.id}>
                    <div>
                      <span>{attendance.participant.displayName}</span>
                      <strong>
                        {formatDateKey(attendance.effectiveDate)} / {participantStatusLabel(attendance.participant.status, locale)} /{" "}
                        {attendanceSourceLabel(attendance.source, locale)}
                      </strong>
                    </div>
                    <form className="row-actions button-row" action={removeGymForgeAdminAttendanceCorrection}>
                      <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                      <input type="hidden" name="attendanceId" value={attendance.id} />
                      <button className="button-danger" type="submit">
                        {t.removeAttendanceCorrection}
                      </button>
                    </form>
                  </div>
                ))}
                {recentAttendances.length === 0 ? (
                  <div className="empty-row">
                    <span>{t.empty}</span>
                    <strong>{t.noRecentAttendance}</strong>
                  </div>
                ) : null}
              </div>
            </div>
          ) : null}
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
                      <option value="BODYWEIGHT">{t.bodyweight}</option>
                      <option value="OTHER">{t.otherUnit}</option>
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
                  <button className="button-primary" type="submit" disabled={activeExercises.length === 0}>
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
              <div className="management-list compact-management-list">
                {viewerWorkouts.map((workout) => (
                  <div className="management-row workout-row" key={workout.id}>
                    <div>
                      <span>
                        {formatDateKey(workout.workoutAt)}
                        {isAdmin ? ` / ${workout.participant.displayName}` : ""}
                      </span>
                      <strong>
                        {workout.sets[0]
                          ? `${workout.sets[0].exercise.name}: ${workout.sets[0].reps} reps`
                          : t.noSets}
                      </strong>
                    </div>
                    <div className="workout-actions">
                      <details className="admin-drawer">
                        <summary>{t.updateWorkout}</summary>
                        <form className="compact-form" action={updateGymForgeWorkout}>
                          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                          <input type="hidden" name="workoutId" value={workout.id} />
                          <label>
                            {t.workoutDate}
                            <input name="workoutAt" type="date" defaultValue={formatDateKey(workout.workoutAt)} required />
                          </label>
                          <label>
                            {t.exercise}
                            <select name="exerciseId" required aria-label={t.exercise} defaultValue={workout.sets[0]?.exerciseId ?? ""}>
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
                            <input name="setNumber" type="number" min={1} max={50} defaultValue={workout.sets[0]?.setNumber ?? 1} required />
                          </label>
                          <label>
                            {t.reps}
                            <input name="reps" type="number" min={1} max={500} defaultValue={workout.sets[0]?.reps ?? 1} required />
                          </label>
                          <label>
                            {t.load}
                            <input
                              name="load"
                              type="number"
                              min={0}
                              max={1000}
                              step="0.01"
                              defaultValue={workout.sets[0]?.load?.toString() ?? ""}
                            />
                          </label>
                          <label>
                            {t.unit}
                            <select name="unit" defaultValue={workout.sets[0]?.unit ?? "KG"} aria-label={t.unit}>
                              <option value="KG">kg</option>
                              <option value="LB">lb</option>
                              <option value="BODYWEIGHT">{t.bodyweight}</option>
                              <option value="OTHER">{t.otherUnit}</option>
                            </select>
                          </label>
                          <label>
                            {t.workoutNote}
                            <input name="workoutNote" maxLength={240} defaultValue={workout.note ?? ""} />
                          </label>
                          <label>
                            {t.setNote}
                            <input name="setNote" maxLength={160} defaultValue={workout.sets[0]?.note ?? ""} />
                          </label>
                          <button className="button-primary" type="submit" disabled={activeExercises.length === 0}>
                            {t.updateWorkout}
                          </button>
                        </form>
                      </details>
                      <details className="admin-drawer danger-zone">
                        <summary>{t.deleteWorkout}</summary>
                        <form className="action-stack button-row" action={deleteGymForgeWorkout}>
                          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                          <input type="hidden" name="workoutId" value={workout.id} />
                          <label className="checkbox-line">
                            <input name="confirmDelete" type="checkbox" value="true" />
                            {t.confirmWorkoutDelete}
                          </label>
                          <button className="button-danger" type="submit">
                            {t.deleteWorkout}
                          </button>
                        </form>
                      </details>
                    </div>
                  </div>
                ))}
                {viewerWorkouts.length === 0 ? (
                  <div className="empty-row">
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

            <div className="management-strip">
              <div className="management-strip-header">
                <div>
                  <span>Admin</span>
                  <strong>{t.participantManagement}</strong>
                </div>
                <span className="management-count">{formatCount(participants.length)}</span>
              </div>

              <details className="admin-drawer create-strip-drawer">
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
                      <option value="PARTICIPANT">{t.participantRole}</option>
                      <option value="ADMIN">{t.adminRole}</option>
                    </select>
                  </label>
                  <label>
                    {t.status}
                    <select name="status" defaultValue="INVITED" aria-label={t.status}>
                      <option value="INVITED">{t.invited}</option>
                      <option value="ACTIVE">{t.activeState}</option>
                      <option value="DISABLED">{t.disabled}</option>
                      <option value="ARCHIVED">{t.archivedStatus}</option>
                    </select>
                  </label>
                  <button className="button-primary" type="submit">{t.createParticipant}</button>
                </form>
              </details>

              <div className="management-list compact-management-list" aria-label={t.participants}>
                {participants.map((participant) => (
                  <div className="management-row" key={participant.id}>
                    <div>
                      <span>{participant.displayName}</span>
                      <strong>{participantRoleLabel(participant.role, locale)} / {participantStatusLabel(participant.status, locale)}</strong>
                    </div>
                    <form className="row-actions button-row" action={changeGymForgeParticipantStatus}>
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

            <div className="management-strip">
              <div className="management-strip-header">
                <div>
                  <span>Admin</span>
                  <strong>{t.exerciseCatalog}</strong>
                </div>
                <span className="management-count">{formatCount(exercises.length)}</span>
              </div>

              <details className="admin-drawer create-strip-drawer">
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

              <div className="management-list compact-management-list" aria-label={t.exercises}>
                {exercises.map((exercise) => (
                  <div className="management-row" key={exercise.id}>
                    <div>
                      <span>{exercise.name}</span>
                      <strong>
                        {exercise.category ?? t.uncategorized} /{" "}
                        {exercise.archivedAt ? t.archivedStatus : exercise.isActive ? t.activeState : t.inactive}
                      </strong>
                    </div>
                    <form className="row-actions button-row" action={changeGymForgeExerciseStatus}>
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
    </CoreShell>
  );
}
