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

const ACCESS_COOKIE = "cd_access";
const REFRESH_COOKIE = "cd_refresh";
// 15 min (aligned with JWT_EXPIRE_MINUTES default).
const ACCESS_MAX_AGE = 15 * 60;
// 7 days (aligned with JWT_REFRESH_EXPIRE_DAYS default).
const REFRESH_MAX_AGE = 7 * 24 * 60 * 60;

function isProd() {
  return process.env.NODE_ENV === "production";
}

function setAuthCookies(res: NextResponse, access?: string, refresh?: string) {
  const base = {
    httpOnly: true,
    secure: isProd(),
    sameSite: "lax" as const,
    path: "/",
  };
  if (access) {
    res.cookies.set({ ...base, name: ACCESS_COOKIE, value: access, maxAge: ACCESS_MAX_AGE });
  }
  if (refresh) {
    // Restreindre l'envoi du refresh aux endpoints qui en ont besoin.
    res.cookies.set({
      ...base,
      name: REFRESH_COOKIE,
      value: refresh,
      maxAge: REFRESH_MAX_AGE,
      path: "/api/proxy/auth",
    });
  }
}

function clearAuthCookies(res: NextResponse) {
  res.cookies.set({ name: ACCESS_COOKIE, value: "", maxAge: 0, path: "/" });
  res.cookies.set({ name: REFRESH_COOKIE, value: "", maxAge: 0, path: "/api/proxy/auth" });
}

async function callBackend(
  targetPath: string,
  search: string,
  method: string,
  headers: Headers,
  body: BodyInit | null,
): Promise<Response> {
  return fetch(`${BACKEND_URL}/${targetPath}${search}`, {
    method,
    headers,
    body,
    redirect: "manual",
  });
}

async function proxy(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  const targetPath = path.join("/");
  const search = req.nextUrl.search ?? "";

  const isLogin = targetPath === "auth/login";
  const isRefresh = targetPath === "auth/refresh";
  const isLogout = targetPath === "auth/logout";

  const headers = new Headers();
  req.headers.forEach((value, key) => {
    if (!HOP_BY_HOP.has(key.toLowerCase())) {
      headers.set(key, value);
    }
  });
  if (API_KEY) {
    headers.set("X-API-Key", API_KEY);
  }

  // Pour /auth/refresh on injecte le refresh depuis le cookie httpOnly,
  // l'utilisateur n'a rien a fournir cote client.
  let bodyBytes: ArrayBuffer | null = null;
  if (req.method !== "GET" && req.method !== "HEAD") {
    bodyBytes = await req.arrayBuffer();
  }

  if (isRefresh && req.method === "POST") {
    const refreshFromCookie = req.cookies.get(REFRESH_COOKIE)?.value;
    if (!refreshFromCookie) {
      return NextResponse.json({ detail: "No refresh cookie" }, { status: 401 });
    }
    bodyBytes = new TextEncoder().encode(
      JSON.stringify({ refresh_token: refreshFromCookie }),
    ).buffer as ArrayBuffer;
    headers.set("Content-Type", "application/json");
  } else {
    // Sur les autres routes, injecte le JWT access depuis le cookie.
    const accessFromCookie = req.cookies.get(ACCESS_COOKIE)?.value;
    if (accessFromCookie && !headers.has("authorization")) {
      headers.set("Authorization", `Bearer ${accessFromCookie}`);
    }

    // Pour /auth/logout, on attache aussi le refresh dans le body afin de le revoquer.
    if (isLogout && req.method === "POST") {
      const refreshFromCookie = req.cookies.get(REFRESH_COOKIE)?.value;
      if (refreshFromCookie) {
        bodyBytes = new TextEncoder().encode(
          JSON.stringify({ refresh_token: refreshFromCookie }),
        ).buffer as ArrayBuffer;
        headers.set("Content-Type", "application/json");
      }
    }
  }

  let upstream: Response;
  let refreshedAccess: string | undefined;
  try {
    upstream = await callBackend(targetPath, search, req.method, headers, bodyBytes);
  } catch (err) {
    return NextResponse.json(
      { error: "Upstream unreachable", detail: String(err) },
      { status: 502 },
    );
  }

  // Si 401 sur un appel non-auth, on tente UN refresh silencieux avec le cookie,
  // puis on rejoue la requete d'origine. Pas de boucle : un seul retry.
  if (
    upstream.status === 401 &&
    !isLogin &&
    !isRefresh &&
    !isLogout &&
    targetPath !== "auth/me"
  ) {
    const refreshCookie = req.cookies.get(REFRESH_COOKIE)?.value;
    if (refreshCookie) {
      const refreshHeaders = new Headers({ "Content-Type": "application/json" });
      if (API_KEY) refreshHeaders.set("X-API-Key", API_KEY);
      const refreshBody = new TextEncoder().encode(
        JSON.stringify({ refresh_token: refreshCookie }),
      ).buffer as ArrayBuffer;
      const refreshResp = await callBackend(
        "auth/refresh", "", "POST", refreshHeaders, refreshBody,
      );
      if (refreshResp.ok) {
        const refreshData = await refreshResp.json().catch(() => ({}));
        const newAccess = refreshData?.access_token;
        const newRefresh = refreshData?.refresh_token;
        if (newAccess) {
          refreshedAccess = newAccess;
          headers.set("Authorization", `Bearer ${newAccess}`);
          upstream = await callBackend(
            targetPath, search, req.method, headers, bodyBytes,
          );
          // Pose les cookies mis a jour sur la reponse finale.
          // Conserves jusqu'a la branche normale plus bas.
          (upstream as Response & { __newAccess?: string; __newRefresh?: string })
            .__newAccess = newAccess;
          (upstream as Response & { __newAccess?: string; __newRefresh?: string })
            .__newRefresh = newRefresh;
        }
      }
    }
  }

  const respHeaders = new Headers();
  upstream.headers.forEach((value, key) => {
    const k = key.toLowerCase();
    if (!HOP_BY_HOP.has(k) && k !== "set-cookie") {
      respHeaders.set(key, value);
    }
  });

  // Login + Refresh : on consomme les jetons et on les pose en cookie.
  // Le body retourne au client n'expose plus le token brut.
  if ((isLogin || isRefresh) && upstream.ok) {
    const text = await upstream.text();
    let access = "";
    let refresh = "";
    let safeBody: unknown = {};
    try {
      const parsed = JSON.parse(text);
      access = parsed?.access_token ?? "";
      refresh = parsed?.refresh_token ?? "";
      safeBody = { token_type: parsed?.token_type ?? "bearer", ok: true };
    } catch {
      safeBody = { ok: true };
    }
    const res = NextResponse.json(safeBody, { status: upstream.status });
    setAuthCookies(res, access, refresh);
    return res;
  }

  if (isLogout) {
    const res = new NextResponse(null, {
      status: upstream.status === 0 ? 204 : upstream.status,
    });
    clearAuthCookies(res);
    return res;
  }

  const finalResp = new NextResponse(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: respHeaders,
  });
  // Si on a obtenu de nouveaux jetons via le refresh silencieux, on les pose.
  const tagged = upstream as Response & { __newAccess?: string; __newRefresh?: string };
  if (refreshedAccess && tagged.__newAccess) {
    setAuthCookies(finalResp, tagged.__newAccess, tagged.__newRefresh);
  }
  return finalResp;
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
