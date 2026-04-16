"use client";

import { useCallback, useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState(""); // auto-generated if empty
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("analyst");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);

  // Browser always goes through the server-side proxy (which injects the API key).
  const BASE = "/api/proxy";

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);
      setSuccess(null);
      setLoading(true);

      try {
        if (mode === "register") {
          const res = await fetch(`${BASE}/auth/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, email: email || `${username}@cyberdef.local`, password, role }),
          });
          if (!res.ok) {
            const body = await res.json().catch(() => ({}));
            throw new Error(body.detail || `Erreur ${res.status}`);
          }
          setSuccess("Compte cree avec succes ! Connectez-vous.");
          setMode("login");
          setLoading(false);
          return;
        }

        // Login
        const res = await fetch(`${BASE}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
        });
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error(body.detail || "Identifiants invalides");
        }
        const data = await res.json();
        localStorage.setItem("jwt_token", data.access_token);
        localStorage.setItem("username", username);

        // Fetch user info
        const meRes = await fetch(`${BASE}/auth/me`, {
          headers: {
            Authorization: `Bearer ${data.access_token}`,
          },
        });
        if (meRes.ok) {
          const user = await meRes.json();
          localStorage.setItem("user_role", user.role);
          localStorage.setItem("user_id", user.id);
        }

        router.push("/");
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Erreur de connexion");
      } finally {
        setLoading(false);
      }
    },
    [mode, username, email, password, role, router],
  );

  return (
    <div className="flex min-h-screen items-center justify-center bg-space-dark">
      {/* Background effects */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 h-96 w-96 rounded-full bg-cyan-glow/5 blur-3xl" />
        <div className="absolute -bottom-40 -right-40 h-96 w-96 rounded-full bg-cyan-glow/5 blur-3xl" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 h-[600px] w-[600px] rounded-full bg-cyan-glow/3 blur-3xl" />
      </div>

      <motion.div
        className="relative z-10 w-full max-w-md px-6"
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: "easeOut" }}
      >
        {/* Logo */}
        <div className="mb-8 flex flex-col items-center gap-3">
          <div className="relative flex h-16 w-16 items-center justify-center">
            <svg viewBox="0 0 36 36" className="h-16 w-16">
              <polygon
                points="18,2 32,10 32,26 18,34 4,26 4,10"
                fill="none"
                stroke="#00E5FF"
                strokeWidth="1.5"
                opacity="0.6"
              />
              <polygon
                points="18,6 28,12 28,24 18,30 8,24 8,12"
                fill="rgba(0, 229, 255, 0.08)"
                stroke="#00E5FF"
                strokeWidth="0.5"
                opacity="0.4"
              />
              <text
                x="18"
                y="21"
                textAnchor="middle"
                fill="#00E5FF"
                fontSize="12"
                fontFamily="Orbitron, sans-serif"
                fontWeight="700"
              >
                CD
              </text>
            </svg>
            <div
              className="absolute inset-0 rounded-full opacity-30 blur-lg"
              style={{ background: "radial-gradient(circle, #00E5FF 0%, transparent 70%)" }}
            />
          </div>
          <div className="text-center">
            <h1 className="hud-heading text-2xl font-bold tracking-widest text-cyan-glow">
              CyberDef
            </h1>
            <p className="text-[10px] tracking-widest text-cyan-glow/30">
              DEFENSE SYSTEM // AUTHENTICATION
            </p>
          </div>
        </div>

        {/* Card */}
        <div className="glass-panel glass-panel-animated p-8">
          {/* Tabs */}
          <div className="mb-6 flex overflow-hidden rounded-md border border-cyan-glow/20">
            {(["login", "register"] as const).map((m) => (
              <button
                key={m}
                onClick={() => { setMode(m); setError(null); setSuccess(null); }}
                className={`flex-1 py-2.5 text-[11px] font-bold tracking-widest transition-all ${
                  mode === m
                    ? "bg-cyan-glow/15 text-cyan-glow"
                    : "bg-transparent text-gray-500 hover:text-gray-300"
                }`}
              >
                {m === "login" ? "CONNEXION" : "INSCRIPTION"}
              </button>
            ))}
          </div>

          {/* Success */}
          {success && (
            <motion.div
              className="mb-4 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-4 py-2.5 text-[11px] text-emerald-400"
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
            >
              {success}
            </motion.div>
          )}

          {/* Error */}
          {error && (
            <motion.div
              className="mb-4 rounded-md border border-red-500/30 bg-red-500/10 px-4 py-2.5 text-[11px] text-red-400"
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
            >
              {error}
            </motion.div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="mb-1.5 block text-[9px] font-bold tracking-widest text-cyan-glow/50 uppercase">
                Nom d&apos;utilisateur
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                placeholder="admin"
                className="w-full rounded-md border border-cyan-glow/20 bg-space-dark/50 px-4 py-2.5 text-sm text-gray-200 font-mono placeholder-gray-600 outline-none transition-all focus:border-cyan-glow/50 focus:shadow-[0_0_12px_rgba(0,229,255,0.1)]"
              />
            </div>

            <div>
              <label className="mb-1.5 block text-[9px] font-bold tracking-widest text-cyan-glow/50 uppercase">
                Mot de passe
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                placeholder="••••••••"
                className="w-full rounded-md border border-cyan-glow/20 bg-space-dark/50 px-4 py-2.5 text-sm text-gray-200 font-mono placeholder-gray-600 outline-none transition-all focus:border-cyan-glow/50 focus:shadow-[0_0_12px_rgba(0,229,255,0.1)]"
              />
            </div>

            {mode === "register" && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
              >
                <label className="mb-1.5 block text-[9px] font-bold tracking-widest text-cyan-glow/50 uppercase">
                  Role
                </label>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="w-full rounded-md border border-cyan-glow/20 bg-space-dark/50 px-4 py-2.5 text-sm text-gray-200 font-mono outline-none transition-all focus:border-cyan-glow/50"
                >
                  <option value="analyst" className="bg-gray-900">Analyst</option>
                  <option value="lead" className="bg-gray-900">Lead</option>
                  <option value="admin" className="bg-gray-900">Admin</option>
                </select>
              </motion.div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="mt-2 flex w-full items-center justify-center gap-2 rounded-md border border-cyan-glow/30 bg-cyan-glow/10 py-3 text-[11px] font-bold tracking-widest text-cyan-glow transition-all hover:bg-cyan-glow/20 hover:shadow-cyan-md active:scale-[0.98] disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {loading && (
                <svg className="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              )}
              {mode === "login"
                ? loading ? "CONNEXION..." : "SE CONNECTER"
                : loading ? "INSCRIPTION..." : "S'INSCRIRE"
              }
            </button>
          </form>
        </div>

        {/* Version */}
        <p className="mt-6 text-center text-[9px] tracking-widest text-cyan-glow/15">
          CYBERDEF v1.0 // SPATIAL UI
        </p>
      </motion.div>
    </div>
  );
}
