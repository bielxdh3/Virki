import { randomBytes } from "node:crypto";
import { NextResponse, type NextRequest } from "next/server";
import { buildPublicContentSecurityPolicy } from "./public-csp";

export function proxy(request: NextRequest) {
  const nonce = randomBytes(16).toString("base64");
  const policy = buildPublicContentSecurityPolicy(process.env.NODE_ENV, nonce);
  const requestHeaders = new Headers(request.headers);
  // Next.js reads the request CSP during rendering to nonce its bootstrap scripts.
  requestHeaders.set("Content-Security-Policy", policy);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", policy);
  return response;
}
