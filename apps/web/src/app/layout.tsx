import type { Metadata } from "next";
import { Sidebar } from "@/components/Sidebar";
import { ChatPanel } from "@/components/ChatPanel";
import { StarField } from "@/components/StarField";
import "./globals.css";

export const metadata: Metadata = {
  title: "Cyber Defense Dashboard",
  description: "Security events and incident management",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head />
      <body className="flex h-screen overflow-hidden bg-space-dark text-gray-100" suppressHydrationWarning>
        <StarField />
        <Sidebar />
        <main className="relative z-10 flex-1 overflow-y-auto p-6">
          {children}
        </main>
        <ChatPanel />
      </body>
    </html>
  );
}
