export const PASSWORD_INPUT_MAX_LENGTH = 256;
export const EMAIL_INPUT_MAX_LENGTH = 320;

export function readBoundedFormString(formData: FormData, key: string, maxLength: number): string | null {
  const value = formData.get(key);
  // JavaScript string length uses UTF-16 code units, matching HTML maxlength.
  return typeof value === "string" && value.length <= maxLength ? value : null;
}
