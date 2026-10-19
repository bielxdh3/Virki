export type AccountStatusValue = "PENDING_ACTIVATION" | "ACTIVE" | "BLOCKED" | "INACTIVE";

export type AccountStateRecord = {
  isActive: boolean;
  accountStatus: AccountStatusValue;
};

export function getAccountStatePresentation(state: AccountStateRecord): { label: string; action: "enable" | "disable" | null } {
  if (state.accountStatus === "ACTIVE") {
    return state.isActive
      ? { label: "Ativa", action: "disable" }
      : { label: "Ativa · estado inconsistente (indicador inativo)", action: null };
  }
  if (state.accountStatus === "INACTIVE") {
    return state.isActive
      ? { label: "Suspensa · estado inconsistente (indicador ativo)", action: null }
      : { label: "Suspensa", action: "enable" };
  }
  return state.accountStatus === "BLOCKED"
    ? { label: "Bloqueada", action: null }
    : { label: "Pendente de ativação", action: null };
}

export function accountStateTransitionWhere(userId: string, enabled: boolean) {
  return {
    id: userId,
    role: "USER" as const,
    isActive: !enabled,
    accountStatus: enabled ? "INACTIVE" as const : "ACTIVE" as const
  };
}
