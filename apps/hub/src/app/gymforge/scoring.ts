const MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;

export const COMPETITION_SCORING_RULES = [
  "ATTENDANCE_COUNT",
  "CURRENT_STREAK",
  "LONGEST_STREAK",
  "ATTENDANCE_PLUS_LONGEST_STREAK"
] as const;

export type CompetitionScoringRule = (typeof COMPETITION_SCORING_RULES)[number];

export type CompetitionScoringInput = {
  startsAt: Date | null;
  endsAt: Date | null;
  scoringRule: string;
  assignments: readonly {
    participantId: string;
    participant: {
      id: string;
      displayName: string;
      status: string;
      attendances: readonly {
        effectiveDate: Date;
      }[];
    };
  }[];
  scoreCorrections: readonly {
    participantId: string;
    pointsDelta: number;
    revokedAt: Date | null;
  }[];
};

export type CompetitionScore = {
  participantId: string;
  displayName: string;
  baseScore: number;
  activeAdjustment: number;
  finalScore: number;
  attendanceCount: number;
  currentStreak: number;
  longestStreak: number;
  latestCheckInDate: Date | null;
};

export function isCompetitionScoringRule(value: string): value is CompetitionScoringRule {
  return COMPETITION_SCORING_RULES.includes(value as CompetitionScoringRule);
}

function toUtcDayNumber(date: Date): number | null {
  const time = date.getTime();
  return Number.isFinite(time) ? Math.floor(time / MILLISECONDS_PER_DAY) : null;
}

function toCanonicalUtcDate(dayNumber: number): Date {
  return new Date(dayNumber * MILLISECONDS_PER_DAY);
}

export function compareCodePointStrings(left: string, right: string): number {
  const leftCodePoints = left[Symbol.iterator]();
  const rightCodePoints = right[Symbol.iterator]();

  while (true) {
    const leftResult = leftCodePoints.next();
    const rightResult = rightCodePoints.next();

    if (leftResult.done || rightResult.done) {
      if (leftResult.done && rightResult.done) {
        return 0;
      }

      return leftResult.done ? -1 : 1;
    }

    const difference = leftResult.value.codePointAt(0)! - rightResult.value.codePointAt(0)!;
    if (difference !== 0) {
      return difference;
    }
  }
}

export function dedupeEffectiveDatesInUtcRange(
  effectiveDates: readonly Date[],
  startsAt: Date,
  endsAt: Date
): Date[] {
  const rangeStart = toUtcDayNumber(startsAt);
  const rangeEnd = toUtcDayNumber(endsAt);

  if (rangeStart === null || rangeEnd === null || startsAt.getTime() > endsAt.getTime()) {
    return [];
  }

  const uniqueDays = new Set<number>();

  for (const effectiveDate of effectiveDates) {
    const day = toUtcDayNumber(effectiveDate);
    if (day !== null && day >= rangeStart && day <= rangeEnd) {
      uniqueDays.add(day);
    }
  }

  return Array.from(uniqueDays)
    .sort((left, right) => left - right)
    .map(toCanonicalUtcDate);
}

export function calculateCurrentStreak(effectiveDates: readonly Date[], anchorDate: Date): number {
  const anchorDay = toUtcDayNumber(anchorDate);
  if (anchorDay === null) {
    return 0;
  }

  const uniqueDays = new Set<number>();
  for (const effectiveDate of effectiveDates) {
    const day = toUtcDayNumber(effectiveDate);
    if (day !== null) {
      uniqueDays.add(day);
    }
  }

  let cursor = uniqueDays.has(anchorDay) ? anchorDay : anchorDay - 1;
  if (!uniqueDays.has(cursor)) {
    return 0;
  }

  let streak = 0;
  while (uniqueDays.has(cursor)) {
    streak += 1;
    cursor -= 1;
  }

  return streak;
}

export function calculateLongestStreak(effectiveDates: readonly Date[]): number {
  const uniqueDays = new Set<number>();
  for (const effectiveDate of effectiveDates) {
    const day = toUtcDayNumber(effectiveDate);
    if (day !== null) {
      uniqueDays.add(day);
    }
  }

  const orderedDays = Array.from(uniqueDays).sort((left, right) => left - right);
  let longestStreak = 0;
  let currentStreak = 0;
  let previousDay: number | null = null;

  for (const day of orderedDays) {
    currentStreak = previousDay !== null && day === previousDay + 1 ? currentStreak + 1 : 1;
    longestStreak = Math.max(longestStreak, currentStreak);
    previousDay = day;
  }

  return longestStreak;
}

function calculateBaseScore(
  scoringRule: CompetitionScoringRule,
  attendanceCount: number,
  currentStreak: number,
  longestStreak: number
): number {
  switch (scoringRule) {
    case "ATTENDANCE_COUNT":
      return attendanceCount;
    case "CURRENT_STREAK":
      return currentStreak;
    case "LONGEST_STREAK":
      return longestStreak;
    case "ATTENDANCE_PLUS_LONGEST_STREAK":
      return attendanceCount + longestStreak;
  }
}

function compareCompetitionScores(left: CompetitionScore, right: CompetitionScore): number {
  if (right.finalScore !== left.finalScore) {
    return right.finalScore - left.finalScore;
  }

  if (right.attendanceCount !== left.attendanceCount) {
    return right.attendanceCount - left.attendanceCount;
  }

  if (right.longestStreak !== left.longestStreak) {
    return right.longestStreak - left.longestStreak;
  }

  const rightLatest = right.latestCheckInDate?.getTime() ?? Number.NEGATIVE_INFINITY;
  const leftLatest = left.latestCheckInDate?.getTime() ?? Number.NEGATIVE_INFINITY;
  if (rightLatest !== leftLatest) {
    return rightLatest - leftLatest;
  }

  const displayNameComparison = compareCodePointStrings(left.displayName, right.displayName);
  return displayNameComparison || compareCodePointStrings(left.participantId, right.participantId);
}

export function calculateCompetitionScores(competition: CompetitionScoringInput): CompetitionScore[] {
  const startsAtTime = competition.startsAt?.getTime();
  const endsAtTime = competition.endsAt?.getTime();

  if (
    startsAtTime === undefined ||
    endsAtTime === undefined ||
    !Number.isFinite(startsAtTime) ||
    !Number.isFinite(endsAtTime) ||
    startsAtTime > endsAtTime ||
    !isCompetitionScoringRule(competition.scoringRule)
  ) {
    return [];
  }

  const activeAdjustments = new Map<string, number>();
  for (const correction of competition.scoreCorrections) {
    if (correction.revokedAt === null) {
      activeAdjustments.set(
        correction.participantId,
        (activeAdjustments.get(correction.participantId) ?? 0) + correction.pointsDelta
      );
    }
  }

  return competition.assignments
    .filter((assignment) => assignment.participant.status === "ACTIVE")
    .map((assignment): CompetitionScore => {
      const effectiveDates = dedupeEffectiveDatesInUtcRange(
        assignment.participant.attendances.map((attendance) => attendance.effectiveDate),
        competition.startsAt!,
        competition.endsAt!
      );
      const attendanceCount = effectiveDates.length;
      const currentStreak = calculateCurrentStreak(effectiveDates, competition.endsAt!);
      const longestStreak = calculateLongestStreak(effectiveDates);
      const baseScore = calculateBaseScore(
        competition.scoringRule as CompetitionScoringRule,
        attendanceCount,
        currentStreak,
        longestStreak
      );
      const activeAdjustment = activeAdjustments.get(assignment.participantId) ?? 0;

      return {
        participantId: assignment.participantId,
        displayName: assignment.participant.displayName,
        baseScore,
        activeAdjustment,
        finalScore: baseScore + activeAdjustment,
        attendanceCount,
        currentStreak,
        longestStreak,
        latestCheckInDate: effectiveDates.at(-1) ?? null
      };
    })
    .sort(compareCompetitionScores);
}
