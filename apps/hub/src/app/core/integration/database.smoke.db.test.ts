import assert from "node:assert/strict";
import { after, test } from "node:test";

import { prisma } from "@bielos/database";

after(async () => {
  await prisma.$disconnect();
});

test("uses a migrated disposable PostgreSQL database and cleans its fixture", async () => {
  assert.equal(process.env.BIELOS_CORE_TEST_DATABASE_CONFIRM, "disposable");

  const databaseRows = await prisma.$queryRaw<Array<{ databaseName: string }>>`
    SELECT current_database() AS "databaseName"
  `;
  assert.match(databaseRows[0]?.databaseName ?? "", /test/i);

  const slug = "core-database-smoke-test";

  try {
    const project = await prisma.project.create({
      data: {
        name: "Core Database Smoke Test",
        slug,
        visibility: "INTERNAL",
        status: "PLANNED"
      },
      select: { slug: true }
    });

    assert.equal(project.slug, slug);
  } finally {
    await prisma.project.deleteMany({ where: { slug } });
  }

  assert.equal(await prisma.project.count({ where: { slug } }), 0);
});
