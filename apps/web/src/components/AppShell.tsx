"use client";

import { usePathname } from "next/navigation";
import { AuthGuard } from "@/components/AuthGuard";
import { Sidebar } from "@/components/Sidebar";
import { ChatPanel } from "@/components/ChatPanel";
import { CommandPalette } from "@/components/CommandPalette";
import { NotificationCenter } from "@/components/NotificationCenter";
import { Breadcrumbs } from "@/components/Breadcrumbs";
import { KeyboardShortcuts } from "@/components/KeyboardShortcuts";
import { Terminal } from "@/components/Terminal";
import { BootScreen } from "@/components/BootScreen";
import { StarField } from "@/components/StarField";
import { FavoriteStarButton } from "@/components/Favorites";
import { CompactToggle } from "@/components/CompactToggle";

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isLogin = pathname === "/login";

  return (
    <BootScreen>
      <AuthGuard>
        <StarField />
        {!isLogin && <Sidebar />}
        <main className={`relative z-10 flex-1 overflow-y-auto ${isLogin ? "" : "p-6"}`}>
          {/* Top bar */}
          {!isLogin && (
            <div className="fixed top-3 right-6 z-50 flex items-center gap-2">
              <CompactToggle />
              <NotificationCenter />
            </div>
          )}
          {/* Breadcrumbs + Favorite star */}
          {!isLogin && (
            <div className="mb-4 flex items-center gap-2">
              <Breadcrumbs />
              <FavoriteStarButton />
            </div>
          )}
          {children}
        </main>
        {!isLogin && <ChatPanel />}
        {!isLogin && <CommandPalette />}
        {!isLogin && <KeyboardShortcuts />}
        {!isLogin && <Terminal />}
      </AuthGuard>
    </BootScreen>
  );
}
