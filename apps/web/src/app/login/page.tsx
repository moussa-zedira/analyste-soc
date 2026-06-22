"use client";

import { useCallback, useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { useAuthStore } from "@/stores/authStore";
import { HudCard, HudButton, HudField, HudInput, HudSelect } from "@/components/hud";

export default function LoginPage() {
  const router = useRouter();
  const { login, register } = useAuthStore();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [email] = useState(""); // auto-generated if empty
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("analyst");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);
      setSuccess(null);
      setLoading(true);

      try {
        if (mode === "register") {
          await register({
            username,
            email: email || `${username}@cyberdef.local`,
            password,
            role,
          });
          setSuccess("Compte cree avec succes ! Connectez-vous.");
          setMode("login");
          setLoading(false);
          return;
        }
        await login(username, password);
        router.push("/");
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Erreur de connexion");
      } finally {
        setLoading(false);
      }
    },
    [mode, username, email, password, role, router, login, register],
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
        <HudCard className="glass-panel-animated p-8">
          {/* Tabs */}
          <div className="mb-6 flex gap-2">
            {(["login", "register"] as const).map((m) => (
              <HudButton
                key={m}
                block
                variant={mode === m ? "primary" : "ghost"}
                onClick={() => { setMode(m); setError(null); setSuccess(null); }}
              >
                {m === "login" ? "CONNEXION" : "INSCRIPTION"}
              </HudButton>
            ))}
          </div>

          {/* Success */}
          {success && (
            <motion.div
              className="glass-panel mb-4 border-matrix-green/40 px-4 py-2.5 text-[11px] text-emerald-400 shadow-matrix-glow"
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
            >
              {success}
            </motion.div>
          )}

          {/* Error */}
          {error && (
            <motion.div
              className="glass-panel mb-4 border-neon-pink/40 px-4 py-2.5 text-[11px] text-neon-pink shadow-alert-glow"
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
            >
              {error}
            </motion.div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <HudField label="Nom d'utilisateur">
              <HudInput
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                placeholder="admin"
                mono
              />
            </HudField>

            <HudField label="Mot de passe">
              <HudInput
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                placeholder="••••••••"
                mono
              />
            </HudField>

            {mode === "register" && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
              >
                <HudField label="Role">
                  <HudSelect value={role} onChange={(e) => setRole(e.target.value)}>
                    <option value="analyst" className="bg-gray-900">Analyst</option>
                    <option value="lead" className="bg-gray-900">Lead</option>
                    <option value="admin" className="bg-gray-900">Admin</option>
                  </HudSelect>
                </HudField>
              </motion.div>
            )}

            <HudButton type="submit" block variant="primary" size="lg" className="mt-2" loading={loading}>
              {mode === "login"
                ? loading ? "CONNEXION..." : "SE CONNECTER"
                : loading ? "INSCRIPTION..." : "S'INSCRIRE"
              }
            </HudButton>
          </form>
        </HudCard>

        {/* Version */}
        <p className="mt-6 text-center text-[9px] tracking-widest text-cyan-glow/15">
          CYBERDEF v1.0 // SPATIAL UI
        </p>
      </motion.div>
    </div>
  );
}
