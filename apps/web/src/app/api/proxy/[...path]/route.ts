import { NextRequest, NextResponse } from "next/server";

// Server-only: not exposed to the browser bundle.
const BACKEND_URL =
  process.env.INTERNAL_API_BASE_URL ??
  process.env.NEXT_PUBLIC_API_BASE_URL ??
  "http://127.0.0.1:8000";
const API_KEY = process.env.INTERNAL_API_KEY ?? "";

const HOP_BY_HOP = new Set([
  "host",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "upgrade",
  "proxy-authorization",
  "proxy-authenticate",
  "trailer",
  "content-length",
  "content-encoding",
]);

async function proxy(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  const targetPath = path.join("/");
  const search = req.nextUrl.search ?? "";
  const target = `${BACKEND_URL}/${targetPath}${search}`;

  const headers = new Headers();
  req.headers.forEach((value, key) => {
    if (!HOP_BY_HOP.has(key.toLowerCase())) {
      headers.set(key, value);
    }
  });
  // Never trust an X-API-Key from the browser; always inject ours.
  if (API_KEY) {
    headers.set("X-API-Key", API_KEY);
  }
  // Forward the user's JWT cookie as Authorization header if present.
  const jwtCookie = req.cookies.get("auth_token")?.value;
  if (jwtCookie && !headers.has("authorization")) {
    headers.set("Authorization", `Bearer ${jwtCookie}`);
  }

  const init: RequestInit = {
    method: req.method,
    headers,
    redirect: "manual",
  };
  if (req.method !== "GET" && req.method !== "HEAD") {
    init.body = await req.arrayBuffer();
  }

  let upstream: Response;
  try {
    upstream = await fetch(target, init);
  } catch (err) {
    return NextResponse.json(
      { error: "Upstream unreachable", detail: String(err) },
      { status: 502 },
    );
  }

  const respHeaders = new Headers();
  upstream.headers.forEach((value, key) => {
    if (!HOP_BY_HOP.has(key.toLowerCase())) {
      respHeaders.set(key, value);
    }
  });

  return new NextResponse(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: respHeaders,
  });
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
export const OPTIONS = proxy;
export const HEAD = proxy;

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
