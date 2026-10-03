"use client";

import { useState, type InputHTMLAttributes } from "react";

type PasswordFieldProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type">;

export function PasswordField(props: PasswordFieldProps) {
  const [visible, setVisible] = useState(false);

  return (
    <div className="password-field">
      <input {...props} type={visible ? "text" : "password"} />
      <button
        type="button"
        aria-label={visible ? "Ocultar senha" : "Mostrar senha"}
        aria-pressed={visible}
        onClick={() => setVisible((current) => !current)}
      >
        {visible ? "Ocultar" : "Mostrar"}
      </button>
    </div>
  );
}
