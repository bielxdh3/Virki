import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import * as ts from "typescript";

const sourceText = readFileSync(new URL("./actions.ts", import.meta.url), "utf8");
const sourceFile = ts.createSourceFile("actions.ts", sourceText, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
const controlsText = readFileSync(new URL("./security-controls.tsx", import.meta.url), "utf8");

const boundaries = [
  { action: "startCredentialSetupAction", fields: ["normalPassword"], credentialOperation: "startAdministrativeCredentialSetup" },
  { action: "completeCredentialSetupAction", fields: ["newPassword", "confirmPassword"], credentialOperation: "completeAdministrativeCredentialSetup" },
  { action: "startElevationAction", fields: ["normalPassword", "administrativePassword"], credentialOperation: "startSecurityElevation" },
  { action: "changeAdminPasswordAction", fields: ["newPassword"], credentialOperation: "changeAdministrativePassword" },
  { action: "recoverAdminCredentialAction", fields: ["normalPassword", "newPassword"], credentialOperation: "recoverAdministrativeCredential" },
  { action: "startAdminEmailRecoveryAction", fields: ["normalPassword"], credentialOperation: "startAdministrativeEmailRecovery" },
  { action: "completeAdminEmailRecoveryAction", fields: ["normalPassword", "newPassword", "confirmPassword"], credentialOperation: "completeAdministrativeEmailRecovery" },
  { action: "recoverAdminCredentialWithTotpAction", fields: ["normalPassword", "newPassword", "confirmPassword", "totpCode"], credentialOperation: "recoverAdministrativeCredentialWithTotp" }
] as const;

function nodesWithin<T extends ts.Node>(root: ts.Node, match: (node: ts.Node) => node is T): T[] {
  const result: T[] = [];
  const visit = (node: ts.Node) => {
    if (match(node)) result.push(node);
    ts.forEachChild(node, visit);
  };
  visit(root);
  return result;
}

function functionNamed(name: string): ts.FunctionDeclaration {
  const declaration = sourceFile.statements.find((statement): statement is ts.FunctionDeclaration =>
    ts.isFunctionDeclaration(statement) && statement.name?.text === name
  );
  assert.ok(declaration?.body, `expected ${name} to remain a function declaration with an inspectable body`);
  return declaration;
}

function callsNamed(root: ts.Node, name: string): ts.CallExpression[] {
  return nodesWithin(root, (node): node is ts.CallExpression =>
    ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === name
  );
}

function hasNullCheck(root: ts.Node, field: string): boolean {
  return nodesWithin(root, ts.isBinaryExpression).some((expression) => {
    if (expression.operatorToken.kind !== ts.SyntaxKind.EqualsEqualsEqualsToken) return false;
    const leftIsField = ts.isIdentifier(expression.left) && expression.left.text === field;
    const rightIsField = ts.isIdentifier(expression.right) && expression.right.text === field;
    return (leftIsField && expression.right.kind === ts.SyntaxKind.NullKeyword)
      || (rightIsField && expression.left.kind === ts.SyntaxKind.NullKeyword);
  });
}

function isNullCheckFor(node: ts.Node, field: string): boolean {
  const expression = ts.isParenthesizedExpression(node) ? node.expression : node;
  return ts.isBinaryExpression(expression) && expression.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken && (
    (ts.isIdentifier(expression.left) && expression.left.text === field && expression.right.kind === ts.SyntaxKind.NullKeyword) ||
    (ts.isIdentifier(expression.right) && expression.right.text === field && expression.left.kind === ts.SyntaxKind.NullKeyword)
  );
}

function rejectsEachNullInputWithOr(expression: ts.Expression, fields: readonly string[]): boolean {
  const disjuncts: ts.Expression[] = [];
  const collect = (node: ts.Expression) => {
    const unwrapped = ts.isParenthesizedExpression(node) ? node.expression : node;
    if (ts.isBinaryExpression(unwrapped) && unwrapped.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
      collect(unwrapped.left);
      collect(unwrapped.right);
    } else {
      disjuncts.push(unwrapped);
    }
  };
  collect(expression);
  if (disjuncts.length !== fields.length) return false;
  const checkedFields = disjuncts.map((disjunct) => fields.find((field) => isNullCheckFor(disjunct, field)));
  return checkedFields.every((field): field is string => field !== undefined) &&
    new Set(checkedFields).size === fields.length && fields.every((field) => checkedFields.includes(field));
}

function returnsGenericError(node: ts.Node): boolean {
  return nodesWithin(node, ts.isReturnStatement).some((statement) => {
    if (!statement.expression || !ts.isObjectLiteralExpression(statement.expression)) return false;
    return statement.expression.properties.some((property) =>
      ts.isPropertyAssignment(property) && property.name.getText(sourceFile) === "status" &&
      ts.isStringLiteral(property.initializer) && property.initializer.text === "error"
    );
  });
}

test("all password-bearing ADMIN actions reject bounded-input failures before credential services", () => {
  for (const boundary of boundaries) {
    const action = functionNamed(boundary.action);
    const formReads = callsNamed(action, "readBoundedFormString");
    const readKeys = formReads.map((call) => {
      assert.equal(call.arguments[0]?.getText(sourceFile), "formData");
      const field = call.arguments[1]?.getText(sourceFile).replace(/^"|"$/gu, "");
      assert.equal(call.arguments[2]?.getText(sourceFile), field === "totpCode" ? "6" : "PASSWORD_INPUT_MAX_LENGTH");
      return field;
    });
    assert.deepEqual(readKeys, boundary.fields, `${boundary.action} must bound every raw password field exactly once`);
    const credentialOperations = callsNamed(action, boundary.credentialOperation);
    assert.equal(credentialOperations.length, 1, `${boundary.action} must have one expected credential service call`);
    assert.ok(formReads.every((read) => read.end < credentialOperations[0]!.pos), `${boundary.action} must bound passwords before credential work`);

    const rejectionGate = nodesWithin(action, ts.isIfStatement).find((statement) =>
      boundary.fields.length === 1
        ? hasNullCheck(statement.expression, boundary.fields[0]!)
        : rejectsEachNullInputWithOr(statement.expression, boundary.fields)
    );
    assert.ok(rejectionGate, `${boundary.action} must branch on every failed bounded input`);
    assert.ok(rejectionGate.end < credentialOperations[0]!.pos, `${boundary.action} must reject invalid input before the credential service`);
    assert.ok(returnsGenericError(rejectionGate.thenStatement), `${boundary.action} must stop with its generic error result`);
  }
});

test("ADMIN credential setup refuses mismatched confirmation before consuming the email proof", () => {
  const action = functionNamed("completeCredentialSetupAction");
  const operation = callsNamed(action, "completeAdministrativeCredentialSetup")[0];
  assert.ok(operation);
  const mismatch = nodesWithin(action, ts.isIfStatement).find((statement) =>
    ts.isBinaryExpression(statement.expression) &&
    statement.expression.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken &&
    statement.expression.left.getText(sourceFile) === "newPassword" &&
    statement.expression.right.getText(sourceFile) === "confirmPassword"
  );
  assert.ok(mismatch, "the two passwords must be compared server-side");
  assert.ok(mismatch.end < operation.pos, "a mismatch must not consume the one-time verification proof");
  assert.ok(nodesWithin(mismatch.thenStatement, ts.isStringLiteral).some((node) => node.text === "password-mismatch"));
});

test("ADMIN email recovery refuses mismatched confirmation before consuming the email proof", () => {
  const action = functionNamed("completeAdminEmailRecoveryAction");
  const operation = callsNamed(action, "completeAdministrativeEmailRecovery")[0];
  assert.ok(operation);
  const mismatch = nodesWithin(action, ts.isIfStatement).find((statement) =>
    ts.isBinaryExpression(statement.expression) &&
    statement.expression.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken &&
    statement.expression.left.getText(sourceFile) === "newPassword" &&
    statement.expression.right.getText(sourceFile) === "confirmPassword"
  );
  assert.ok(mismatch, "the new ADMIN password must be confirmed server-side");
  assert.ok(mismatch.end < operation.pos, "mismatch must never consume the email proof");
});

test("ADMIN TOTP recovery confirms password and uses authenticated hub mutation guard before any credential write", () => {
  const action = functionNamed("recoverAdminCredentialWithTotpAction");
  const operation = callsNamed(action, "recoverAdministrativeCredentialWithTotp")[0];
  const guard = callsNamed(action, "requireAdminMutation")[0];
  assert.ok(operation && guard);
  assert.ok(guard.end < operation.pos);
  assert.equal(guard.arguments[0]?.getText(sourceFile), "formData");
  assert.equal(guard.arguments[1]?.getText(sourceFile), '"admin-totp-credential-recovery"');
  const mismatch = nodesWithin(action, ts.isIfStatement).find((statement) =>
    ts.isBinaryExpression(statement.expression) &&
    statement.expression.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken &&
    statement.expression.left.getText(sourceFile) === "newPassword" &&
    statement.expression.right.getText(sourceFile) === "confirmPassword"
  );
  assert.ok(mismatch && mismatch.end < operation.pos);
  assert.ok(nodesWithin(mismatch.thenStatement, ts.isStringLiteral).some((node) => node.text === "password-mismatch"));
  const guardSource = readFileSync(new URL("../../../lib/admin-mutation.ts", import.meta.url), "utf8");
  assert.match(guardSource, /isHubAdminMutationSurface\(surface\)/u);
  assert.match(guardSource, /validateHubCloudflareAccess\(requestHeaders, source\)/u);
  assert.match(guardSource, /hasSameOrigin\(requestHeaders\)/u);
  assert.match(guardSource, /validateSessionCsrfTokenFor\(sessionToken, csrf, getAdminCsrfScope\(source\)\)/u);
  assert.match(guardSource, /getCurrentSession\(\)/u);
});

test("TOTP ADMIN credential recovery is only shown for ACTIVE factor and requires one-time-code acknowledgement", () => {
  assert.match(controlsText, /totpActive && !emailComplete\.recoveryCodes/u);
  assert.match(controlsText, /action=\{totpRecoveryAction\}/u);
  assert.match(controlsText, /name="csrfToken" value=\{csrf\}/u);
  assert.match(controlsText, /name="totpCode" inputMode="numeric"/u);
  assert.match(controlsText, /totpRecovery\.recoveryCodes/u);
  assert.match(controlsText, /destination="\/admin\/security\?status=totp-recovered#admin-content"/u);
});

test("email credential recovery UI requires fresh normal password, OTP and new password confirmation", () => {
  assert.match(controlsText, /name="requestKey" value=\{emailStart\.requestKey\}/u);
  assert.match(controlsText, /name="code" inputMode="numeric" autoComplete="one-time-code"/u);
  assert.match(controlsText, /name="confirmPassword" type="password" autoComplete="new-password"/u);
  assert.match(controlsText, /startAdminEmailRecoveryAction/u);
  assert.match(controlsText, /completeAdminEmailRecoveryAction/u);
  assert.match(controlsText, /emailComplete\.recoveryCodes/u);
});

test("credential setup UI asks for confirmation and gates one-time code dismissal", () => {
  assert.match(controlsText, /name="confirmPassword" type="password" autoComplete="new-password"/u);
  assert.match(controlsText, /complete\.status === "password-mismatch"/u);
  assert.match(controlsText, /disabled=\{!recoveryCodesSaved\}/u);
  assert.match(controlsText, /disabled=\{!saved\}/u);
  assert.equal((controlsText.match(/Guardei os dez códigos de recuperação fora do Virki/g) ?? []).length, 2);
});
