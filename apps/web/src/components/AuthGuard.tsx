"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";

const PUBLIC_ROUTES = ["/login"];

export function AuthGuard({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [status, setStatus] = useState<"loading" | "ok" | "redirect">("loading");

  useEffect(() => {
    if (PUBLIC_ROUTES.includes(pathname)) {
      setStatus("ok");
      return;
    }

    const token = localStorage.getItem("jwt_token");
    if (!token) {
      setStatus("redirect");
      router.replace("/login");
    } else {
      setStatus("ok");
    }
  }, [pathname, router]);

  if (status === "loading" || status === "redirect") {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-space-dark">
        <div className="flex flex-col items-center gap-3">
          <div className="relative h-10 w-10">
            <div className="absolute inset-0 rounded-full border-2 border-cyan-glow/20 animate-ping" />
            <div className="absolute inset-2 rounded-full border-2 border-t-cyan-glow border-transparent animate-spin" />
          </div>
          <p className="text-[10px] tracking-widest text-cyan-glow/40 animate-pulse">
            {status === "redirect" ? "REDIRECTING..." : "LOADING..."}
          </p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
