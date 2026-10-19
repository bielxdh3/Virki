import React from "react";
import { CSRF_FORM_FIELD_NAME } from "@virki/auth/csrf";
import { setAccountStateAction } from "../actions";
import { getAccountStatePresentation, type AccountStatusValue } from "./account-state-policy";

type AccountStateUser = {
  id: string;
  email: string;
  displayName: string | null;
  isActive: boolean;
  accountStatus: AccountStatusValue;
  secondFactorMethod: "EMAIL" | "TOTP";
  projectGrantCount: number;
};

export function AccountStateRow({ user, csrf }: { user: AccountStateUser; csrf: string }) {
  const state = getAccountStatePresentation(user);
  return <article className="list-row">
    <div className="row-main"><strong>{user.displayName || user.email}</strong><span>{user.email} · {state.label} · MFA {user.secondFactorMethod === "TOTP" ? "TOTP" : "e-mail"} · {user.projectGrantCount} acessos</span></div>
    {state.action && <form action={setAccountStateAction}>
      <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrf} /><input type="hidden" name="userId" value={user.id} /><input type="hidden" name="enabled" value={state.action === "enable" ? "true" : "false"} />
      <button className={state.action === "disable" ? "button-danger" : ""} type="submit">{state.action === "disable" ? "Suspender" : "Reativar"}</button>
    </form>}
  </article>;
}
