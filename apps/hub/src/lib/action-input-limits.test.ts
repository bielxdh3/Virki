import assert from "node:assert/strict";
import test from "node:test";
import { EMAIL_INPUT_MAX_LENGTH, PASSWORD_INPUT_MAX_LENGTH, readBoundedFormString } from "./action-input-limits";

test("raw Server Action fields use the existing UTF-16 password and email limits", () => {
  const formData = new FormData();
  const maxPassword = "😀".repeat(PASSWORD_INPUT_MAX_LENGTH / 2);
  const maxEmail = "a".repeat(315) + "@x.co";
  assert.equal(maxPassword.length, 256);
  assert.equal(maxEmail.length, EMAIL_INPUT_MAX_LENGTH);

  formData.set("password", maxPassword);
  formData.set("email", maxEmail);
  assert.equal(readBoundedFormString(formData, "password", PASSWORD_INPUT_MAX_LENGTH), maxPassword);
  assert.equal(readBoundedFormString(formData, "email", EMAIL_INPUT_MAX_LENGTH), maxEmail);

  formData.set("password", `${maxPassword}x`);
  formData.set("email", `${maxEmail}x`);
  assert.equal(readBoundedFormString(formData, "password", PASSWORD_INPUT_MAX_LENGTH), null);
  assert.equal(readBoundedFormString(formData, "email", EMAIL_INPUT_MAX_LENGTH), null);

  formData.set("password", "😀".repeat(PASSWORD_INPUT_MAX_LENGTH / 2 + 1));
  assert.equal(readBoundedFormString(formData, "password", PASSWORD_INPUT_MAX_LENGTH), null, "supplementary Unicode characters count as two UTF-16 units each");
  formData.set("password", new Blob(["password"]), "password.txt");
  assert.equal(readBoundedFormString(formData, "password", PASSWORD_INPUT_MAX_LENGTH), null, "File values are not accepted as password strings");
});
