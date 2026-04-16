import type { Metadata } from "next";
import { AppShell } from "@/components/AppShell";
import { QueryProvider } from "@/components/QueryProvider";
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
        <QueryProvider>
          <AppShell>{children}</AppShell>
        </QueryProvider>
      </body>
    </html>
  );
}
