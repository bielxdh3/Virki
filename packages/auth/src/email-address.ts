import { domainToASCII } from "node:url";

// Keep UTF-8 local parts and IDN domains supported, while rejecting all
// display-name, comment, quoted-address, header and address-list syntax.
const PLAIN_MAILBOX = /^[^\s@<>()[\],;:"\\]+@[^\s@<>()[\],;:"\\]+$/u;
const DNS_LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u;

export function isSingleMailboxAddress(value: string): boolean {
  if (value.length === 0 || value.length > 254 || !PLAIN_MAILBOX.test(value)) return false;
  const [localPart, domain] = value.split("@");
  const asciiDomain = domain ? domainToASCII(domain) : "";
  return Boolean(localPart && domain && Buffer.byteLength(localPart, "utf8") <= 64 &&
    !localPart.startsWith(".") && !localPart.endsWith(".") && !localPart.includes("..") &&
    !/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(value) &&
    asciiDomain.length <= 253 && asciiDomain.split(".").length >= 2 &&
    asciiDomain.split(".").every((label) => label.length <= 63 && DNS_LABEL.test(label)));
}
