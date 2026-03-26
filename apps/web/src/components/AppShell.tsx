"use client";

import { usePathname } from "next/navigation";
import { AuthGuard } from "@/components/AuthGuard";
import { Sidebar } from "@/components/Sidebar";
import { ChatPanel } from "@/components/ChatPanel";
import { StarField } from "@/components/StarField";

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isLogin = pathname === "/login";

  return (
    <AuthGuard>
      <StarField />
      {!isLogin && <Sidebar />}
      <main className={`relative z-10 flex-1 overflow-y-auto ${isLogin ? "" : "p-6"}`}>
        {children}
      </main>
      {!isLogin && <ChatPanel />}
    </AuthGuard>
  );
}
