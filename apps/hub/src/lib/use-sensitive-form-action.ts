"use client";

import { useCallback, useEffect, useState, useTransition } from "react";
import { flushSync } from "react-dom";
import { registerSensitivePageScrub, scrubSensitivePageSnapshot } from "./sensitive-page-lifecycle";

type FormStateAction<State> = (previousState: State, formData: FormData) => Promise<State>;

export function useSensitiveFormAction<State>(
  action: FormStateAction<State>,
  initialState: State,
): [State, (formData: FormData) => void, boolean] {
  const [state, setState] = useState(initialState);
  const [pending, startTransition] = useTransition();

  const dispatch = useCallback((formData: FormData) => {
    startTransition(async () => {
      const nextState = await action(state, formData);
      setState(nextState);
    });
  }, [action, state]);

  useEffect(() => registerSensitivePageScrub(window, () => {
    flushSync(() => scrubSensitivePageSnapshot(
      () => setState(initialState),
      document.querySelectorAll<HTMLElement>("[data-sensitive-one-time-value]"),
    ));
  }), [initialState]);

  return [state, dispatch, pending];
}
