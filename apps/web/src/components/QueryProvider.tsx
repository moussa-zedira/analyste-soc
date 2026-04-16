"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";

export function QueryProvider({ children }: { children: React.ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            // SOC : evite de masquer une donnee perimee derriere une UI figee.
            staleTime: 15_000,
            gcTime: 5 * 60_000,
            refetchOnWindowFocus: false,
            retry: (failureCount, error) => {
              // Pas de retry sur les 4xx (auth, NotFound, validation).
              const msg = (error as Error)?.message ?? "";
              if (/\b(401|403|404|422)\b/.test(msg)) return false;
              return failureCount < 2;
            },
          },
        },
      }),
  );
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}
