import assert from "node:assert/strict";
import test from "node:test";
import { PrismaClient } from "./index";

test("database workspace exports the PrismaClient runtime constructor", () => {
  assert.equal(typeof PrismaClient, "function");
});
