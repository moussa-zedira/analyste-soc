"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

interface Engagement {
  id: string;
  name: string;
  client_name: string;
}

interface NamedRef {
  name: string;
}

interface TargetIn {
  email: string;
  first_name: string;
  last_name: string;
  position: string;
}

function parseTargets(raw: string): TargetIn[] {
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const parts = line.split(",").map((s) => s.trim());
      return {
        email: parts[0] || "",
        first_name: parts[1] || "",
        last_name: parts[2] || "",
        position: parts[3] || "",
      };
    })
    .filter((t) => t.email.includes("@"));
}

export default function NewCampaignForm() {
  const router = useRouter();

  const [name, setName] = useState("");
  const [engagementId, setEngagementId] = useState("");
  const [templateName, setTemplateName] = useState("");
  const [landingPage, setLandingPage] = useState("");
  const [landingUrl, setLandingUrl] = useState("");
  const [smtpProfile, setSmtpProfile] = useState("");
  const [groupName, setGroupName] = useState("");
  const [targetsRaw, setTargetsRaw] = useState("");
  const [launchDate, setLaunchDate] = useState("");
  const [sendByDate, setSendByDate] = useState("");
  const [notes, setNotes] = useState("");

  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [templates, setTemplates] = useState<NamedRef[]>([]);
  const [pages, setPages] = useState<NamedRef[]>([]);
  const [smtpProfiles, setSmtpProfiles] = useState<NamedRef[]>([]);
  const [groups, setGroups] = useState<NamedRef[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [gpReady, setGpReady] = useState<boolean | null>(null);

  useEffect(() => {
    fetch("/api/proxy/redteam/engagements", { credentials: "include" })
      .then((r) => (r.ok ? r.json() : []))
      .then((d) =>
        setEngagements(
          Array.isArray(d) ? d : Array.isArray(d?.items) ? d.items : [],
        ),
      )
      .catch(() => {});

    fetch("/api/proxy/redteam/phishing/templates", { credentials: "include" })
      .then((r) => {
        if (r.status === 503) {
          setGpReady(false);
          return null;
        }
        setGpReady(true);
        return r.json();
      })
      .then((d) => {
        if (!d) return;
        const list: NamedRef[] = [];
        if (Array.isArray(d?.gophish)) {
          for (const t of d.gophish) {
            if (t?.name) list.push({ name: t.name });
          }
        }
        if (Array.isArray(d?.builtin)) {
          for (const t of d.builtin) {
            if (t?.name) list.push({ name: `${t.name} (builtin)` });
          }
        }
        setTemplates(list);
      })
      .catch(() => {});

    fetch("/api/proxy/redteam/phishing/pages", { credentials: "include" })
      .then((r) => (r.ok ? r.json() : []))
      .then((d) =>
        setPages(
          Array.isArray(d)
            ? d.filter((x: NamedRef) => x?.name).map((x: NamedRef) => ({ name: x.name }))
            : [],
        ),
      )
      .catch(() => {});

    fetch("/api/proxy/redteam/phishing/smtp-profiles", {
      credentials: "include",
    })
      .then((r) => (r.ok ? r.json() : []))
      .then((d) =>
        setSmtpProfiles(
          Array.isArray(d)
            ? d.filter((x: NamedRef) => x?.name).map((x: NamedRef) => ({ name: x.name }))
            : [],
        ),
      )
      .catch(() => {});

    fetch("/api/proxy/redteam/phishing/groups", { credentials: "include" })
      .then((r) => (r.ok ? r.json() : []))
      .then((d) =>
        setGroups(
          Array.isArray(d)
            ? d.filter((x: NamedRef) => x?.name).map((x: NamedRef) => ({ name: x.name }))
            : [],
        ),
      )
      .catch(() => {});
  }, []);

  async function submit() {
    setError(null);
    if (!name || !templateName || !landingUrl || !smtpProfile) {
      setError(
        "name, template_name, landing_url and smtp_profile are required.",
      );
      return;
    }
    const tlist = parseTargets(targetsRaw);
    if (!groupName && tlist.length === 0) {
      setError("Provide either an existing group OR a list of targets.");
      return;
    }

    const payload: Record<string, unknown> = {
      name,
      engagement_id: engagementId || null,
      template_name: templateName.replace(/ \(builtin\)$/, ""),
      landing_page: landingPage,
      landing_url: landingUrl,
      smtp_profile: smtpProfile,
      group_name: groupName,
      targets: tlist,
      notes,
    };
    if (launchDate) payload.launch_date = new Date(launchDate).toISOString();
    if (sendByDate)
      payload.send_by_date = new Date(sendByDate).toISOString();

    setSubmitting(true);
    try {
      const res = await fetch("/api/proxy/redteam/phishing/campaigns", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(`HTTP ${res.status} ${txt.slice(0, 300)}`);
      }
      const data = await res.json();
      router.push(`/redteam/phishing/${data.id}`);
    } catch (e) {
      setError(String(e));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex flex-col gap-4 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-lg font-bold tracking-widest text-cyan-glow">
            NEW PHISHING CAMPAIGN
          </h1>
          <p className="text-[11px] tracking-wider text-cyan-glow/50">
            GOPHISH BACKEND // MITRE T1566.001 // AUDIT SIGNED
          </p>
        </div>
        <button
          onClick={() => router.push("/redteam/phishing")}
          className="rounded border border-cyan-glow/20 px-3 py-1 text-xs tracking-widest text-cyan-glow/70 hover:bg-cyan-glow/10"
        >
          ← BACK
        </button>
      </div>

      {gpReady === false && (
        <div className="rounded-md border border-amber-400/30 bg-amber-500/10 p-3 text-xs text-amber-300">
          GoPhish not configured. The form is disabled. Set{" "}
          <code className="font-mono">GOPHISH_API_URL</code> /{" "}
          <code className="font-mono">GOPHISH_API_KEY</code>.
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-md border border-cyan-glow/20 bg-space-dark/60 p-4">
          <h2 className="mb-3 text-xs font-bold tracking-widest text-cyan-glow/80">
            CAMPAIGN
          </h2>
          <div className="flex flex-col gap-3">
            <Field
              label="NAME"
              value={name}
              onChange={setName}
              placeholder="ACME prod 2026-Q2"
            />
            <Select
              label="ENGAGEMENT (OPTIONAL)"
              value={engagementId}
              onChange={setEngagementId}
              options={[
                { value: "", label: "— none —" },
                ...engagements.map((e) => ({
                  value: e.id,
                  label: `${e.name} · ${e.client_name}`,
                })),
              ]}
            />
            <Field
              label="NOTES"
              value={notes}
              onChange={setNotes}
              placeholder="Scope / pretext / IOCs..."
            />
          </div>
        </div>

        <div className="rounded-md border border-cyan-glow/20 bg-space-dark/60 p-4">
          <h2 className="mb-3 text-xs font-bold tracking-widest text-cyan-glow/80">
            GOPHISH REFS
          </h2>
          <div className="flex flex-col gap-3">
            <Select
              label="TEMPLATE"
              value={templateName}
              onChange={setTemplateName}
              options={[
                { value: "", label: "— select template —" },
                ...templates.map((t) => ({ value: t.name, label: t.name })),
              ]}
            />
            <Select
              label="LANDING PAGE (OPTIONAL)"
              value={landingPage}
              onChange={setLandingPage}
              options={[
                { value: "", label: "— none —" },
                ...pages.map((p) => ({ value: p.name, label: p.name })),
              ]}
            />
            <Field
              label="LANDING URL"
              value={landingUrl}
              onChange={setLandingUrl}
              placeholder="https://login.example-acme.com/"
            />
            <Select
              label="SMTP PROFILE"
              value={smtpProfile}
              onChange={setSmtpProfile}
              options={[
                { value: "", label: "— select smtp —" },
                ...smtpProfiles.map((s) => ({
                  value: s.name,
                  label: s.name,
                })),
              ]}
            />
          </div>
        </div>

        <div className="rounded-md border border-cyan-glow/20 bg-space-dark/60 p-4 lg:col-span-2">
          <h2 className="mb-3 text-xs font-bold tracking-widest text-cyan-glow/80">
            AUDIENCE
          </h2>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Select
              label="EXISTING GROUP (OPTIONAL)"
              value={groupName}
              onChange={setGroupName}
              options={[
                { value: "", label: "— create from targets below —" },
                ...groups.map((g) => ({ value: g.name, label: g.name })),
              ]}
            />
            <div className="flex flex-col gap-1 text-xs tracking-wider text-cyan-glow/70">
              SCHEDULING (UTC, OPTIONAL)
              <div className="grid grid-cols-2 gap-2">
                <input
                  type="datetime-local"
                  value={launchDate}
                  onChange={(e) => setLaunchDate(e.target.value)}
                  className="rounded border border-cyan-glow/20 bg-black/40 px-2 py-1 text-sm text-cyan-glow"
                />
                <input
                  type="datetime-local"
                  value={sendByDate}
                  onChange={(e) => setSendByDate(e.target.value)}
                  className="rounded border border-cyan-glow/20 bg-black/40 px-2 py-1 text-sm text-cyan-glow"
                />
              </div>
            </div>
          </div>
          <label className="mt-3 flex flex-col gap-1 text-xs tracking-wider text-cyan-glow/70">
            TARGETS — one per line: email,first_name,last_name,position
            <textarea
              value={targetsRaw}
              onChange={(e) => setTargetsRaw(e.target.value)}
              placeholder="alice@acme.com,Alice,Wonder,Engineer&#10;bob@acme.com,Bob,Smith,Manager"
              rows={6}
              className="rounded border border-cyan-glow/20 bg-black/40 px-2 py-1 font-mono text-xs text-cyan-glow"
            />
          </label>
        </div>
      </div>

      {error && (
        <div className="rounded border border-red-400/40 bg-red-500/10 p-3 text-xs text-red-300">
          {error}
        </div>
      )}

      <div className="flex justify-end">
        <button
          onClick={submit}
          disabled={submitting || gpReady === false}
          className="rounded border border-cyan-glow/40 bg-cyan-glow/15 px-4 py-2 text-xs tracking-widest text-cyan-glow hover:bg-cyan-glow/25 disabled:opacity-40"
        >
          {submitting ? "LAUNCHING..." : "LAUNCH CAMPAIGN"}
        </button>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="flex flex-col gap-1 text-xs tracking-wider text-cyan-glow/70">
      {label}
      <input
        type="text"
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className="rounded border border-cyan-glow/20 bg-black/40 px-2 py-1 text-sm text-cyan-glow"
      />
    </label>
  );
}

function Select({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <label className="flex flex-col gap-1 text-xs tracking-wider text-cyan-glow/70">
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded border border-cyan-glow/20 bg-black/40 px-2 py-1 text-sm text-cyan-glow"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}
