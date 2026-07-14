import assert from "node:assert/strict";
import test from "node:test";

import {
  calculateCompetitionScores,
  type CompetitionScoringInput,
  type CompetitionScoringRule
} from "./scoring";

const utcDate = (value: string): Date => new Date(`${value}T00:00:00.000Z`);

function assignment(
  participantId: string,
  displayName: string,
  attendanceDates: readonly Date[] = [],
  status = "ACTIVE"
): CompetitionScoringInput["assignments"][number] {
  return {
    participantId,
    participant: {
      id: participantId,
      displayName,
      status,
      attendances: attendanceDates.map((effectiveDate) => ({ effectiveDate }))
    }
  };
}

function competition(overrides: Partial<CompetitionScoringInput> = {}): CompetitionScoringInput {
  return {
    startsAt: utcDate("2026-01-01"),
    endsAt: utcDate("2026-01-04"),
    scoringRule: "ATTENDANCE_COUNT",
    assignments: [],
    scoreCorrections: [],
    ...overrides
  };
}

test("calculates every supported scoring rule", () => {
  const attendanceDates = [utcDate("2026-01-01"), utcDate("2026-01-02"), utcDate("2026-01-04")];
  const expectedBaseScores: Record<CompetitionScoringRule, number> = {
    ATTENDANCE_COUNT: 3,
    CURRENT_STREAK: 1,
    LONGEST_STREAK: 2,
    ATTENDANCE_PLUS_LONGEST_STREAK: 5
  };

  for (const [scoringRule, expectedBaseScore] of Object.entries(expectedBaseScores)) {
    const scores = calculateCompetitionScores(
      competition({
        scoringRule,
        assignments: [assignment("participant-1", "Ada", attendanceDates)]
      })
    );

    assert.deepEqual(scores, [
      {
        participantId: "participant-1",
        displayName: "Ada",
        baseScore: expectedBaseScore,
        activeAdjustment: 0,
        finalScore: expectedBaseScore,
        attendanceCount: 3,
        currentStreak: 1,
        longestStreak: 2,
        latestCheckInDate: utcDate("2026-01-04")
      }
    ]);
  }
});

test("deduplicates UTC dates and keeps the inclusive competition range", () => {
  const scores = calculateCompetitionScores(
    competition({
      startsAt: utcDate("2026-01-02"),
      endsAt: new Date("2026-01-04T23:59:59.999Z"),
      assignments: [
        assignment("participant-1", "Ada", [
          new Date("2026-01-01T23:59:59.999Z"),
          new Date("2026-01-02T01:00:00.000Z"),
          new Date("2026-01-02T22:00:00.000Z"),
          new Date("2026-01-04T23:59:59.999Z"),
          utcDate("2026-01-05")
        ])
      ]
    })
  );

  assert.equal(scores[0]?.attendanceCount, 2);
  assert.equal(scores[0]?.baseScore, 2);
  assert.deepEqual(scores[0]?.latestCheckInDate, utcDate("2026-01-04"));
});

test("sums additive and negative corrections, excludes revoked corrections, and allows negative totals", () => {
  const scores = calculateCompetitionScores(
    competition({
      endsAt: utcDate("2026-01-02"),
      assignments: [
        assignment("participant-1", "Ada", [utcDate("2026-01-01"), utcDate("2026-01-02")])
      ],
      scoreCorrections: [
        { participantId: "participant-1", pointsDelta: 5, revokedAt: null },
        { participantId: "participant-1", pointsDelta: -10, revokedAt: null },
        { participantId: "participant-1", pointsDelta: 100, revokedAt: utcDate("2026-01-03") }
      ]
    })
  );

  assert.equal(scores[0]?.baseScore, 2);
  assert.equal(scores[0]?.activeAdjustment, -5);
  assert.equal(scores[0]?.finalScore, -3);
});

test("returns only assigned active participants", () => {
  const scores = calculateCompetitionScores(
    competition({
      assignments: [
        assignment("active", "Active", [utcDate("2026-01-01")]),
        assignment("inactive", "Inactive", [utcDate("2026-01-01")], "INACTIVE")
      ],
      scoreCorrections: [{ participantId: "inactive", pointsDelta: 1000, revokedAt: null }]
    })
  );

  assert.deepEqual(scores.map((score) => score.participantId), ["active"]);
});

test("returns no scores for open, invalid, reversed, or unsupported competition inputs", () => {
  const invalidInputs: Partial<CompetitionScoringInput>[] = [
    { startsAt: null },
    { endsAt: null },
    { startsAt: new Date(Number.NaN) },
    { endsAt: new Date(Number.NaN) },
    { startsAt: utcDate("2026-01-05"), endsAt: utcDate("2026-01-04") },
    { scoringRule: "UNKNOWN_RULE" }
  ];

  for (const overrides of invalidInputs) {
    assert.deepEqual(
      calculateCompetitionScores(
        competition({
          assignments: [assignment("participant-1", "Ada", [utcDate("2026-01-02")])],
          ...overrides
        })
      ),
      []
    );
  }
});

test("is invariant to assignment, attendance, and correction input order", () => {
  const input = competition({
    assignments: [
      assignment("participant-b", "B", [
        utcDate("2026-01-04"),
        utcDate("2026-01-02"),
        new Date("2026-01-02T18:00:00.000Z")
      ]),
      assignment("participant-a", "A", [utcDate("2026-01-03"), utcDate("2026-01-04")])
    ],
    scoreCorrections: [
      { participantId: "participant-a", pointsDelta: -1, revokedAt: null },
      { participantId: "participant-b", pointsDelta: 2, revokedAt: utcDate("2026-01-04") },
      { participantId: "participant-a", pointsDelta: 3, revokedAt: null }
    ]
  });
  const reversedInput = competition({
    ...input,
    assignments: [...input.assignments]
      .reverse()
      .map((item) => ({
        ...item,
        participant: {
          ...item.participant,
          attendances: [...item.participant.attendances].reverse()
        }
      })),
    scoreCorrections: [...input.scoreCorrections].reverse()
  });

  assert.deepEqual(calculateCompetitionScores(reversedInput), calculateCompetitionScores(input));
});

test("uses every deterministic tie-breaker including code-point names and participant IDs", () => {
  const assignments = [
    assignment("count-one", "Count one", [utcDate("2026-01-04")]),
    assignment("longest-two", "Longest two", [utcDate("2026-01-01"), utcDate("2026-01-02")]),
    assignment("latest-five", "Latest five", [utcDate("2026-01-03"), utcDate("2026-01-05")]),
    assignment("latest-four", "Latest four", [utcDate("2026-01-02"), utcDate("2026-01-04")]),
    assignment("latest-three", "Latest three", [utcDate("2026-01-01"), utcDate("2026-01-03")]),
    assignment("same-b", "Same"),
    assignment("same-a", "Same"),
    assignment("zed", "Zed"),
    assignment("accent", "\u00c1lvaro")
  ];
  const scoreCorrections = assignments
    .map((item) => ({
      participantId: item.participantId,
      pointsDelta: -item.participant.attendances.length,
      revokedAt: null
    }))
    .filter((correction) => correction.pointsDelta !== 0);

  const scores = calculateCompetitionScores(
    competition({ endsAt: utcDate("2026-01-06"), assignments, scoreCorrections })
  );

  assert.deepEqual(scores.map((score) => score.participantId), [
    "longest-two",
    "latest-five",
    "latest-four",
    "latest-three",
    "count-one",
    "same-a",
    "same-b",
    "zed",
    "accent"
  ]);
});

test("does not clamp an accumulated correction above the per-row bound", () => {
  const scores = calculateCompetitionScores(
    competition({
      assignments: [assignment("participant-1", "Ada")],
      scoreCorrections: [
        { participantId: "participant-1", pointsDelta: 1000, revokedAt: null },
        { participantId: "participant-1", pointsDelta: 1000, revokedAt: null }
      ]
    })
  );

  assert.equal(scores[0]?.activeAdjustment, 2000);
  assert.equal(scores[0]?.finalScore, 2000);
});
