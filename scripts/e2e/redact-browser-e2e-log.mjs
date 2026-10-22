const sensitiveHeaderPattern = /^([ \t]*(?:authorization|proxy-authorization|cookie|set-cookie|cf-access-jwt-assertion)[ \t]*:[ \t]*)[^\r\n]*(\r?\n)?$/iu;
const sensitiveAssignmentPattern = /(["']?(?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|password(?:hash)?|secret|csrf[_-]?(?:token|signing[_-]?key)|recovery[_-]?(?:code|token|key)|request[_-]?(?:key|token)|authorization|cf-access-jwt-assertion)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}\]]+)/giu;
const bearerPattern = /(\bBearer\s+)[A-Za-z0-9._~+/-]+=*/giu;
const absoluteUrlPattern = /\bhttps?:\/\/[^\s"'<>]+/giu;
const relativeUrlPattern = /(^|[\s("'=])(\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*\?[^\s"'<>]*)/gmu;

export function redactBrowserE2ELog(input) {
  if (typeof input !== "string") throw new TypeError("Browser E2E output must be text.");

  return input.split(/(?<=\n)/u).map((line) => {
    const headerMatch = line.match(sensitiveHeaderPattern);
    if (headerMatch) return `${headerMatch[1]}[REDACTED]${headerMatch[2] ?? ""}`;

    return line
      .replace(absoluteUrlPattern, redactUrl)
      .replace(relativeUrlPattern, (_match, prefix, url) => `${prefix}${redactUrl(url)}`)
      .replace(bearerPattern, "$1[REDACTED]")
      .replace(sensitiveAssignmentPattern, "$1[REDACTED]");
  }).join("");
}

function redactUrl(url) {
  const trailingPunctuation = url.match(/[),.;!?\]]+$/u)?.[0] ?? "";
  const value = trailingPunctuation ? url.slice(0, -trailingPunctuation.length) : url;
  const queryIndex = value.indexOf("?");
  if (queryIndex >= 0) return `${value.slice(0, queryIndex)}?[REDACTED_QUERY]${trailingPunctuation}`;

  const fragmentIndex = value.indexOf("#");
  if (fragmentIndex >= 0) return `${value.slice(0, fragmentIndex)}#[REDACTED_FRAGMENT]${trailingPunctuation}`;
  return url;
}

if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1].replaceAll("\\", "/")) {
  let input = "";
  for await (const chunk of process.stdin) input += chunk.toString("utf8");
  process.stdout.write(redactBrowserE2ELog(input));
}
