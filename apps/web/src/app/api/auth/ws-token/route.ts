import { NextRequest, NextResponse } from "next/server";

/**
 * Expose le JWT access (cookie HttpOnly ``cd_access``) au client pour
 * qu'il puisse l'attacher en query param ``?token=`` lors d'un handshake
 * WebSocket. Les WebSockets navigateur ne portent pas naturellement les
 * cookies cross-origin/path, et le proxy Next ne sait pas upgrader vers
 * une connexion WebSocket — d'ou ce contournement.
 *
 * La route est protegee par la presence d'un cookie d'auth valide ; pas
 * de body, pas de log du token. Le token retourne reste tres court
 * (15 min — meme TTL que cd_access).
 */

const ACCESS_COOKIE = "cd_access";

export async function GET(req: NextRequest) {
  const token = req.cookies.get(ACCESS_COOKIE)?.value;
  if (!token) {
    return NextResponse.json({ detail: "no access cookie" }, { status: 401 });
  }
  return NextResponse.json(
    { token },
    {
      status: 200,
      headers: {
        "Cache-Control": "no-store, no-cache, must-revalidate",
        Pragma: "no-cache",
      },
    },
  );
}

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
