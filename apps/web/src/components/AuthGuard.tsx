"use client";

import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuthStore } from "@/stores/authStore";

const PUBLIC_ROUTES = ["/login"];

export function AuthGuard({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { status, refreshMe } = useAuthStore();

  useEffect(() => {
    if (PUBLIC_ROUTES.includes(pathname)) return;
    if (status === "idle") {
      void refreshMe();
    }
  }, [pathname, status, refreshMe]);

  useEffect(() => {
    if (PUBLIC_ROUTES.includes(pathname)) return;
    if (status === "unauthenticated") {
      router.replace("/login");
    }
  }, [pathname, status, router]);

  if (PUBLIC_ROUTES.includes(pathname)) {
    return <>{children}</>;
  }

  if (status === "authenticated") {
    return <>{children}</>;
  }

  return (
    <div className="flex h-screen w-full items-center justify-center bg-space-dark">
      <div className="flex flex-col items-center gap-3">
        <div className="relative h-10 w-10">
          <div className="absolute inset-0 rounded-full border-2 border-cyan-glow/20 animate-ping" />
          <div className="absolute inset-2 rounded-full border-2 border-t-cyan-glow border-transparent animate-spin" />
        </div>
        <p className="text-[10px] tracking-widest text-cyan-glow/40 animate-pulse">
          {status === "unauthenticated" ? "REDIRECTING..." : "LOADING..."}
        </p>
      </div>
    </div>
  );
}
