"""Generate Workflows_Analyste_SOC.pdf — 15 workflows concrets.

Utilise reportlab. Les 15 workflows sont ancres sur les 30 pages UI
reellement disponibles + les integrations reelles (Sliver, GoPhish,
BloodHound, Ollama, RAG).
"""

from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

CYAN = colors.HexColor("#00B3CC")
DARK = colors.HexColor("#0A1929")
GRAY = colors.HexColor("#6B7280")
LIGHT = colors.HexColor("#F3F4F6")
GREEN = colors.HexColor("#10B981")
ORANGE = colors.HexColor("#F59E0B")
RED = colors.HexColor("#DC2626")


def build_styles():
    base = getSampleStyleSheet()
    styles = {
        "Title": ParagraphStyle(
            "TitleX", parent=base["Title"], fontSize=26, textColor=DARK,
            spaceAfter=12, leading=30, fontName="Helvetica-Bold",
        ),
        "Subtitle": ParagraphStyle(
            "SubtitleX", parent=base["Normal"], fontSize=12, textColor=GRAY,
            spaceAfter=18, leading=16, fontName="Helvetica-Oblique",
        ),
        "H1": ParagraphStyle(
            "H1X", parent=base["Heading1"], fontSize=18, textColor=CYAN,
            spaceBefore=14, spaceAfter=8, leading=22, fontName="Helvetica-Bold",
        ),
        "H2": ParagraphStyle(
            "H2X", parent=base["Heading2"], fontSize=13, textColor=DARK,
            spaceBefore=10, spaceAfter=4, leading=16, fontName="Helvetica-Bold",
        ),
        "Body": ParagraphStyle(
            "BodyX", parent=base["Normal"], fontSize=10, textColor=DARK,
            leading=14, spaceAfter=6, alignment=TA_LEFT,
        ),
        "Bullet": ParagraphStyle(
            "BulletX", parent=base["Normal"], fontSize=10, textColor=DARK,
            leading=14, leftIndent=14, bulletIndent=2, spaceAfter=3,
        ),
        "Code": ParagraphStyle(
            "CodeX", parent=base["Code"], fontSize=9, textColor=DARK,
            leading=12, leftIndent=8, rightIndent=8, spaceAfter=6,
            backColor=LIGHT, borderPadding=6, fontName="Courier",
        ),
        "Meta": ParagraphStyle(
            "MetaX", parent=base["Normal"], fontSize=8.5, textColor=GRAY,
            leading=11, spaceAfter=4, fontName="Helvetica-Oblique",
        ),
    }
    return styles


def header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(GRAY)
    canvas.drawString(2 * cm, 1.2 * cm, "Analyste SOC — 15 Workflows")
    canvas.drawRightString(
        A4[0] - 2 * cm, 1.2 * cm, f"Page {doc.page}"
    )
    canvas.setStrokeColor(CYAN)
    canvas.setLineWidth(0.5)
    canvas.line(2 * cm, 1.6 * cm, A4[0] - 2 * cm, 1.6 * cm)
    canvas.restoreState()


def mk_workflow_table(rows, styles):
    data = [[Paragraph(f"<b>{k}</b>", styles["Body"]), Paragraph(v, styles["Body"])] for k, v in rows]
    t = Table(data, colWidths=[3.2 * cm, 13 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.5, GRAY),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, GRAY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def section_badge(text, color):
    return Table(
        [[Paragraph(f"<font color='white'><b>{text}</b></font>",
                    ParagraphStyle("badge", fontSize=9, textColor=colors.white))]],
        colWidths=[4 * cm],
        style=TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), color),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]),
    )


WORKFLOWS = [
    # ========== SOC DEFENSIF ==========
    {
        "num": 1,
        "cat": "SOC DEFENSIF",
        "cat_color": GREEN,
        "title": "Triage rapide d'un incident critique avec AI + RAG",
        "objective": "Qualifier un incident critique (TP/FP/review) en < 3 minutes avec verdict IA + contexte historique RAG, puis passer a l'action.",
        "tools": "/incidents, /ai/triage, /ai/rag, /soar/playbooks",
        "steps": [
            "Ouvrir /incidents et cliquer sur l'incident critique en haut de la liste.",
            "Copier l'incident_id puis ouvrir /ai/triage, onglet 'By Incident ID', coller l'ID et lancer le triage (provider auto).",
            "Verifier le verdict (true_positive / false_positive / needs_review), la confiance, les techniques MITRE et les IOCs extraits.",
            "Si confiance < 70 %, ouvrir /ai/rag et rechercher les elements cles de l'incident (IP source, username, event_type) sur 168h de corpus.",
            "Decider : si TP -> /soar/playbooks pour declencher le playbook de confinement ; si FP -> fermer avec le tag 'false_positive' ; si review -> assigner.",
            "Documenter la decision dans la timeline de l'incident (note + evidences MITRE/IOCs)."
        ],
        "success": "Verdict pris, action declenchee, incident transitionne et documente.",
        "time": "2 a 5 min",
    },
    {
        "num": 2,
        "cat": "SOC DEFENSIF",
        "cat_color": GREEN,
        "title": "Threat hunting — detection brute force multi-IP sur 24h",
        "objective": "Identifier les campagnes de brute force distribue (low-and-slow) qui echappent aux seuils classiques.",
        "tools": "/search (CQL), /hunting, /ioc",
        "steps": [
            "Ouvrir /search et charger la query predefinie 'Brute Force Detection' depuis la library.",
            "Adapter la fenetre (-24h latest=now) et ajuster le seuil (where count > 10 -> > 5 pour low-and-slow).",
            "Exporter les src_ip resultats (bouton Export CSV).",
            "Pivoter chaque IP suspecte dans /threat-intel (AbuseIPDB + OTX) pour score reputation.",
            "Creer un IOC dans /ioc pour chaque IP confirmee malveillante (TTL 30j, confidence 80, tags : 'brute-force', 'auth').",
            "Sauvegarder la query modifiee en 'saved query' pour execution hebdo (schedule: 0 6 * * 1)."
        ],
        "success": "Liste d'IPs malveillantes enrichies en IOCs reutilisables + query sauvegardee pour repetition.",
        "time": "15 a 30 min",
    },
    {
        "num": 3,
        "cat": "SOC DEFENSIF",
        "cat_color": GREEN,
        "title": "Enrichissement IOC et propagation sur events historiques",
        "objective": "A partir d'un nouvel IOC (IP/domain/hash), retro-chercher les events historiques qui l'ont touche sans etre detectes.",
        "tools": "/ioc, /search, /incidents",
        "steps": [
            "Ajouter le nouvel IOC dans /ioc (type, value, source, confidence, TTL).",
            "Le systeme enrichit auto via threat intel (VirusTotal/OTX si configures).",
            "Ouvrir /search et lancer une CQL : 'src_ip=\"<ioc>\" OR dst_ip=\"<ioc>\" | stats count by host, event_type | sort -count'.",
            "Pour chaque host touche, ouvrir le timeline detaille (| timechart count by event_type).",
            "Si correlation suspecte, creer un incident manuel depuis /incidents avec lien vers l'IOC et la query.",
            "Exporter le resultat en JSON pour investigation forensic externe."
        ],
        "success": "Chaque host touche par l'IOC est identifie avec sa chronologie.",
        "time": "10 a 20 min",
    },
    {
        "num": 4,
        "cat": "SOC DEFENSIF",
        "cat_color": GREEN,
        "title": "Generation et deploiement d'une regle Sigma par IA",
        "objective": "Passer d'un incident recent a une regle de detection deployable, sans ecrire de Sigma a la main.",
        "tools": "/ai/rule-gen, /ai/triage, /search",
        "steps": [
            "Selectionner un incident TP recent (ex: lateral movement via psexec).",
            "Ouvrir /ai/rule-gen et fournir : description courte + extrait de log + MITRE technique (T1021.002).",
            "L'IA genere une regle Sigma avec detection, condition, level, tags.",
            "Tester la regle contre le corpus : copier le pattern en CQL dans /search et verifier qu'elle match l'event source ET qu'elle ne sature pas en FP.",
            "Si OK : valider et deployer (le backend convertit Sigma -> regle de correlation active).",
            "Monitorer les 48h suivantes via /alerts pour confirmer les matches."
        ],
        "success": "Nouvelle regle deployee, testee, monitoree. Detection coverage MITRE augmentee.",
        "time": "20 a 40 min",
    },
    {
        "num": 5,
        "cat": "SOC DEFENSIF",
        "cat_color": GREEN,
        "title": "Execution d'un playbook SOAR sur incident majeur",
        "objective": "Automatiser la reponse sur un incident (confinement, enrichissement, notification) via un playbook pre-defini.",
        "tools": "/soar/playbooks, /soar/executions, /incidents, /alerts",
        "steps": [
            "Depuis /incidents, ouvrir un incident de type 'malware.detect' ou 'ransomware'.",
            "Ouvrir /soar/playbooks, choisir le playbook 'Malware Containment' (ou equivalent).",
            "Fournir les inputs (incident_id, host, user). Le playbook execute : isolation host, kill process, snapshot, notif Slack.",
            "Suivre l'execution en live dans /soar/executions (status par etape).",
            "Verifier les resultats : channel Slack dans /alerts, audit log, evidences attachees a l'incident.",
            "Si l'une des etapes echoue, cliquer 'Retry step' ou passer en manuel."
        ],
        "success": "Host isole, evidences collectees, equipe notifiee, timeline incident mise a jour.",
        "time": "5 a 10 min (machine) + review analyste",
    },
    # ========== RED TEAM ==========
    {
        "num": 6,
        "cat": "RED TEAM",
        "cat_color": RED,
        "title": "Reconnaissance OSINT complete d'une cible externe",
        "objective": "Construire un profil attaquant d'une cible (domaine client engagement) en une passe automatisee.",
        "tools": "/recon, /pentest/subdomain, /pentest/crawler, /pentest/netscan",
        "steps": [
            "Ouvrir /recon et lancer un scan multi-modules sur le domaine (subdomain + certs + tech_stack + emails).",
            "Pendant que /recon tourne, ouvrir /pentest/subdomain en parallele pour une passe DNS + CT logs + wordlist plus profonde.",
            "A la fin, exporter les subdomains actifs en liste.",
            "Pour chaque subdomain web, lancer /pentest/crawler (profondeur 2, formulaires + endpoints caches).",
            "Pour les subdomains avec services exposes, lancer /pentest/netscan (fingerprint services + versions).",
            "Consolider : une liste finale URLs / services / versions / emails a partir des 4 modules."
        ],
        "success": "Surface d'attaque complete cartographiee, prete a etre passee en phase exploitation.",
        "time": "30 a 90 min selon la taille du scope",
    },
    {
        "num": 7,
        "cat": "RED TEAM",
        "cat_color": RED,
        "title": "Pipeline pentest web auto — recon -> SQLi -> XSS -> rapport",
        "objective": "Exploiter un site web avec la chaine auto sans intervention manuelle entre les etapes.",
        "tools": "/pentest/pipeline, /pentest/sqli, /pentest/xss-engine, /reports",
        "steps": [
            "Ouvrir /pentest/pipeline et creer un pipeline 'Web Quick Assess'.",
            "Etapes : crawler (profondeur 2) -> sqli (5 techniques, auto-detect DBMS) -> xss-engine (6 contexts) -> report.",
            "Cibler l'URL, valider le scope (doit matcher un engagement actif avec kill-switch inactif).",
            "Lancer. Monitorer la progression (chaque etape produit des findings stockees en DB).",
            "Si SQLi hit : ouvrir /pentest/sqli pour raffiner (tamper, extraction donnees).",
            "Si XSS hit : ouvrir /pentest/xss-engine pour generer payload contextuel final.",
            "Generer le rapport final dans /reports (template pentest technique, avec preuves et recommandations)."
        ],
        "success": "Rapport pentest web complet en PDF, vulnerabilites classees CVSS + OWASP.",
        "time": "1 a 3h",
    },
    {
        "num": 8,
        "cat": "RED TEAM",
        "cat_color": RED,
        "title": "Campagne phishing GoPhish scopee avec kill-switch",
        "objective": "Lancer une campagne phishing controlee, avec enforcement strict du scope RoE et observation temps reel.",
        "tools": "/redteam/phishing, GoPhish (:3333), /alerts",
        "steps": [
            "Depuis /redteam/phishing, verifier que l'engagement cible est actif et que le kill-switch est off.",
            "Creer une campagne : template email + landing page + liste cibles (CSV importe).",
            "Scope check : le backend verifie que TOUS les domaines cibles matchent le scope RoE de l'engagement, sinon refus.",
            "Envoi : le backend push vers GoPhish via API, puis sync engine regulier met a jour les compteurs (sent/opened/clicked/submitted).",
            "Monitorer en live le taux de clic et les credentials submits.",
            "Si incident (plainte client, hors scope) : activer le kill-switch engagement -> stop auto de la campagne GoPhish, audit trail ecrit."
        ],
        "success": "Campagne executee dans le scope, metriques collectees, rapport de conformite RoE disponible.",
        "time": "2 a 4h (campagne dure plusieurs jours)",
    },
    {
        "num": 9,
        "cat": "RED TEAM",
        "cat_color": RED,
        "title": "Operations Sliver C2 — listener -> implant -> session -> pivot",
        "objective": "Etablir une session C2 operationnelle et pivoter vers les machines voisines via BloodHound.",
        "tools": "/pentest/c2, /redteam/console, /redteam/bloodhound",
        "steps": [
            "Verifier que Sliver daemon tourne (localhost:31337) et est configure dans .env.",
            "Ouvrir /pentest/c2, onglet 'Listeners' : creer un listener HTTPS sur le port cible (ex: :8443).",
            "Onglet 'Implants' : generer un implant Python/PowerShell avec callback URL + beacon interval + obfuscation.",
            "Deployer l'implant sur la cible (phishing payload, recup credentials, etc.).",
            "Attendre la session dans /redteam/console (event 'session.new' via WS).",
            "Ouvrir le terminal live, executer 'whoami /priv', 'ipconfig /all', 'net user /domain'.",
            "Si dataset BloodHound importe : ouvrir le pivot read-only a droite pour voir les chemins d'attaque depuis cette session (local admins, high-value targets)."
        ],
        "success": "Session Sliver active + pivot BloodHound affichant au moins un chemin vers un high-value asset.",
        "time": "30 min a plusieurs jours",
    },
    {
        "num": 10,
        "cat": "RED TEAM",
        "cat_color": RED,
        "title": "Import BloodHound + analyse chemins d'attaque",
        "objective": "Exploiter un dump AD (SharpHound/AzureHound) pour identifier les quick-wins de privesc/lateral.",
        "tools": "/redteam/bloodhound, /redteam/console",
        "steps": [
            "Recuperer le dump SharpHound (zip avec json users/groups/computers/sessions).",
            "Ouvrir /redteam/bloodhound et creer un nouveau dataset associe a l'engagement.",
            "Upload du zip. Le backend parse et stocke les noeuds/relations (peut prendre quelques minutes).",
            "Dataset chargee : ouvrir la vue graph, naviguer entre users/computers/groups.",
            "Lancer des queries pre-built : 'Shortest path to Domain Admins', 'Users with DCSync rights', 'Kerberoastable users'.",
            "Pour chaque chemin critique, copier les edges en notes (bouton 'COPY AS NOTE' dans le pivot).",
            "Si une session Sliver correspond a un noeud du dataset, le pivot de /redteam/console montre auto les paths depuis cette session."
        ],
        "success": "Liste priorisee de chemins d'attaque valides + notes copiees dans le rapport d'engagement.",
        "time": "1 a 2h selon taille du dump",
    },
    # ========== POST-EXPLOIT ==========
    {
        "num": 11,
        "cat": "POST-EXPLOIT",
        "cat_color": ORANGE,
        "title": "Credential harvesting + vault + reutilisation cross-session",
        "objective": "Extraire credentials browser/cloud/secrets depuis une session compromise, les stocker chiffres (Fernet), les reutiliser.",
        "tools": "/redteam/console + modules backend /post-exploit/*",
        "steps": [
            "Depuis une session Sliver active, executer les modules post-exploit : browser (Chrome, Firefox, Edge), cloud (AWS/Azure CLI files), secrets (env vars, config files).",
            "Les creds extraits sont pushes auto dans le Credential Vault (chiffrement Fernet, audit log).",
            "Consulter le vault via l'API (/post-exploit/vault/list) : type, source_host, value (dechiffree a l'affichage seulement).",
            "Utiliser une cred extraite pour une 2e session : passer l'username/password a /pentest/brute sur un service voisin (SSH/RDP/SMB).",
            "Si match : nouvelle session Sliver demandee sur ce host, pivot lateral complet.",
            "Tout l'usage est audite (qui utilise quelle cred, sur quelle cible)."
        ],
        "success": "Credentials extraits + chiffres + reutilises avec succes pour un pivot lateral.",
        "time": "45 min a 2h",
    },
    {
        "num": 12,
        "cat": "POST-EXPLOIT",
        "cat_color": ORANGE,
        "title": "Brute force cible sur service decouvert en recon",
        "objective": "Cracker un service exposé (SSH/HTTP login/FTP) avec wordlist + rules apres l'avoir trouve en recon.",
        "tools": "/pentest/netscan, /pentest/brute",
        "steps": [
            "Apres /pentest/netscan, reperer un service login exposé (ex: SSH :22 sur un subdomain).",
            "Ouvrir /pentest/brute, choisir le protocole, renseigner host:port.",
            "Fournir la liste des usernames (depuis /recon emails) et la wordlist password (rockyou.txt, ou generee par wordgen).",
            "Configurer : delai entre tentatives (anti-lockout), max parallel connexions, kill-switch sur trigger (ex: 50 fails consecutifs).",
            "Lancer le brute force. Monitorer les findings en temps reel.",
            "Si hit : cred ajoute auto au Credential Vault, incident cree cote SOC (boucle bleue/rouge deliberee sur la plateforme)."
        ],
        "success": "Cred obtenue sur le service ou abandonnee proprement dans le scope.",
        "time": "30 min a plusieurs heures",
    },
    {
        "num": 13,
        "cat": "POST-EXPLOIT",
        "cat_color": ORANGE,
        "title": "Cartographie reseau interne + lateral post-C2",
        "objective": "Une fois C2 etabli, cartographier le reseau interne et identifier les prochaines cibles laterales.",
        "tools": "/redteam/console, /pentest/netscan, /redteam/bloodhound",
        "steps": [
            "Depuis la session Sliver active, executer 'arp -a', 'route print', 'netstat -rn' pour lister voisins et gateway.",
            "Upload ces donnees dans /pentest/netscan pour structuration (network map).",
            "Lancer un ping sweep + port scan sur le /24 local depuis la session (via Sliver execute, pas depuis l'attaquant directement).",
            "Correler avec le dataset BloodHound : croiser les IPs decouvertes avec les ordinateurs AD et leurs relations.",
            "Identifier 3-5 targets prioritaires (high value, admin paths, shortest).",
            "Pour chaque target, preparer un playbook lateral (pass-the-hash, overpass, kerberoast selon le contexte)."
        ],
        "success": "Carte reseau interne + 3 targets prioritaires valides + plan lateral.",
        "time": "1 a 3h",
    },
    # ========== REPORTING / ADMIN ==========
    {
        "num": 14,
        "cat": "REPORTING",
        "cat_color": CYAN,
        "title": "Rapport engagement final — MITRE coverage + exec summary",
        "objective": "Produire le rapport livrable client avec mapping MITRE automatique et resume executif.",
        "tools": "/reports, /redteam/bloodhound, /pentest/c2, /redteam/phishing",
        "steps": [
            "Verifier que l'engagement est 'closed' et que toutes les findings/sessions/campagnes sont rattachees.",
            "Ouvrir /reports, choisir le template 'Engagement Final' (executive + technique).",
            "Le backend agrege : findings web, sessions C2, credentials, campagnes phishing, chemins BloodHound.",
            "Revue du draft : verifier l'exec summary genere par l'IA, ajuster les paragraphes sensibles.",
            "MITRE coverage : le rapport contient auto un MITRE Navigator export des techniques reellement utilisees.",
            "Export PDF + remise client (via canal securise, hors plateforme).",
            "Archiver l'engagement : audit trail signe + snapshot DB pour tracabilite 7 ans."
        ],
        "success": "PDF livrable conforme (exec + technique + MITRE + annexes), pret a etre remis.",
        "time": "1 a 2h de revue apres generation auto",
    },
    {
        "num": 15,
        "cat": "ADMIN",
        "cat_color": CYAN,
        "title": "Audit securite interne de la plateforme (users, API keys, 2FA)",
        "objective": "Verifier que la plateforme elle-meme respecte les bonnes pratiques (hygiene comptes + acces).",
        "tools": "/admin, /profile, audit logs",
        "steps": [
            "Ouvrir /admin et lister tous les users (filter par role : admin, analyst, read-only).",
            "Verifier : chaque admin a 2FA active ; pas de compte dormant > 90j ; mots de passe changes recemment.",
            "Ouvrir /admin -> API keys : lister les cles, verifier last_used, rotation > 180j, scope minimal.",
            "Revoquer les cles non utilisees depuis 90j+.",
            "Verifier /admin -> audit logs : actions sensibles (user creation, role change, key gen) tracees.",
            "Tester le recovery flow sur un compte test (forgot password + 2FA recovery code).",
            "Documenter le tout dans un rapport d'audit interne (template /reports existe)."
        ],
        "success": "Comptes proprees, cles rotees, rapport d'audit interne archive pour conformite.",
        "time": "1 a 2h par trimestre",
    },
]


def main():
    out = Path("C:/Users/Pa/Documents/analyste-soc/docs/Workflows_Analyste_SOC.pdf")
    styles = build_styles()

    doc = SimpleDocTemplate(
        str(out), pagesize=A4,
        rightMargin=2 * cm, leftMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title="15 Workflows — Analyste SOC",
        author="Plateforme Analyste SOC",
    )

    story = []
    # --- Cover ---
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("15 Workflows Operationnels", styles["Title"]))
    story.append(Paragraph(
        "Guide pratique — Plateforme Analyste SOC",
        styles["Subtitle"],
    ))
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph(
        "<b>Perimetre</b> : ce document decrit 15 workflows concrets exploitant "
        "uniquement les outils deja integres et operationnels dans ta plateforme "
        "(30 pages UI + Sliver C2 + GoPhish + BloodHound + Ollama/Claude + "
        "RAG sur 11k docs + Credential Vault).",
        styles["Body"],
    ))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        "<b>Organisation</b> : 4 categories — SOC defensif (5), Red Team (5), "
        "Post-exploit (3), Reporting/Admin (2). Chaque workflow detaille objectif, "
        "outils utilises, etapes ordonnees, critere de succes et temps estime.",
        styles["Body"],
    ))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        "<b>Usage</b> : suivre en sequence OU piocher a la carte selon le contexte. "
        "Chaque etape est traduisible en action reelle dans la plateforme, pas un "
        "exercice theorique.",
        styles["Body"],
    ))
    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph(
        f"Genere le 2026-04-21 | Version plateforme V5 | 30 routes UI | "
        f"1046 endpoints API",
        styles["Meta"],
    ))

    # --- Table of contents (simple) ---
    story.append(PageBreak())
    story.append(Paragraph("Sommaire", styles["H1"]))
    story.append(Spacer(1, 0.3 * cm))
    toc_data = [["#", "Categorie", "Workflow", "Duree"]]
    for w in WORKFLOWS:
        toc_data.append([
            str(w["num"]),
            w["cat"],
            w["title"][:55] + ("…" if len(w["title"]) > 55 else ""),
            w["time"],
        ])
    toc = Table(toc_data, colWidths=[1 * cm, 3.2 * cm, 9.5 * cm, 3.3 * cm])
    toc.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), CYAN),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOX", (0, 0), (-1, -1), 0.5, GRAY),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, GRAY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(toc)

    # --- Workflows ---
    current_cat = None
    for w in WORKFLOWS:
        if w["cat"] != current_cat:
            story.append(PageBreak())
            story.append(section_badge(w["cat"], w["cat_color"]))
            story.append(Spacer(1, 0.4 * cm))
            current_cat = w["cat"]
        else:
            story.append(Spacer(1, 0.6 * cm))

        # Title
        story.append(Paragraph(
            f"Workflow {w['num']:02d} — {w['title']}", styles["H1"]
        ))

        # Meta table
        story.append(mk_workflow_table([
            ("Objectif", w["objective"]),
            ("Outils", w["tools"]),
            ("Duree", w["time"]),
            ("Succes", w["success"]),
        ], styles))

        # Steps
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("Etapes", styles["H2"]))
        for i, step in enumerate(w["steps"], 1):
            story.append(Paragraph(
                f"<b>{i}.</b> {step}", styles["Bullet"]
            ))

    # --- Closing ---
    story.append(PageBreak())
    story.append(Paragraph("En resume", styles["H1"]))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        "Ces 15 workflows couvrent le cycle complet que ta plateforme supporte "
        "aujourd'hui, du triage defensif au reporting post-engagement. "
        "Chacun est executable <b>immediatement</b>, sans module manquant ni "
        "dependance externe non configuree.",
        styles["Body"],
    ))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        "<b>Prochaines etapes suggerees</b> :", styles["H2"]
    ))
    for item in [
        "Executer 1 workflow par categorie cette semaine pour valider end-to-end.",
        "Mesurer les temps reels vs estimations et ajuster.",
        "Documenter les deltas dans /pentest/docs (sections internes).",
        "Pour les workflows 4, 7, 14 : capturer un screencast de demonstration.",
        "Si une etape echoue, ouvrir un ticket avec l'endpoint + payload + reponse.",
    ]:
        story.append(Paragraph(f"- {item}", styles["Bullet"]))

    story.append(Spacer(1, 0.8 * cm))
    story.append(Paragraph(
        "<i>Document genere automatiquement par scripts/gen_workflows_pdf.py — "
        "regenerer a chaque ajout de module important.</i>",
        styles["Meta"],
    ))

    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    print(f"OK -> {out}")


if __name__ == "__main__":
    main()
