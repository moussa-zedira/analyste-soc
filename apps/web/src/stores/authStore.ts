"use client";

import { create } from "zustand";

export type AuthUser = {
  id: string;
  username: string;
  email: string;
  role: "analyst" | "lead" | "admin";
  is_active: boolean;
  created_at?: string;
};

type AuthState = {
  user: AuthUser | null;
  status: "idle" | "loading" | "authenticated" | "unauthenticated";
  error: string | null;
  login: (username: string, password: string) => Promise<void>;
  register: (data: {
    username: string;
    email: string;
    password: string;
    role?: string;
  }) => Promise<void>;
  refreshMe: () => Promise<void>;
  logout: () => Promise<void>;
};

const PROXY = "/api/proxy";

async function postJson(path: string, body: unknown): Promise<Response> {
  return fetch(`${PROXY}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    credentials: "include",
  });
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  status: "idle",
  error: null,

  async login(username, password) {
    set({ status: "loading", error: null });
    const res = await postJson("/auth/login", { username, password });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      set({ status: "unauthenticated", error: body.detail ?? "Identifiants invalides" });
      throw new Error(body.detail ?? "Identifiants invalides");
    }
    await get().refreshMe();
  },

  async register({ username, email, password, role = "analyst" }) {
    set({ status: "loading", error: null });
    const res = await postJson("/auth/register", { username, email, password, role });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      set({ status: "unauthenticated", error: body.detail ?? `Erreur ${res.status}` });
      throw new Error(body.detail ?? `Erreur ${res.status}`);
    }
    set({ status: "unauthenticated" });
  },

  async refreshMe() {
    const res = await fetch(`${PROXY}/auth/me`, { credentials: "include" });
    if (!res.ok) {
      set({ user: null, status: "unauthenticated" });
      return;
    }
    const user = (await res.json()) as AuthUser;
    set({ user, status: "authenticated", error: null });
  },

  async logout() {
    await postJson("/auth/logout", {}).catch(() => undefined);
    set({ user: null, status: "unauthenticated", error: null });
  },
}));
