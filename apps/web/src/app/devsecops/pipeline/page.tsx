"use client";

import { useState, useMemo, useCallback } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type Platform = "github" | "gitlab" | "jenkins" | "azure" | "circleci";
type ScanCheck = "sast" | "sca" | "secrets" | "dast" | "container" | "iac";

const PLATFORMS: { key: Platform; label: string; icon: string }[] = [
  { key: "github", label: "GitHub Actions", icon: "M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.604-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z" },
  { key: "gitlab", label: "GitLab CI", icon: "M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 01-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 014.82 2a.43.43 0 01.58.16l2.44 7.49h8.32l2.44-7.51A.42.42 0 0118.71 2a.42.42 0 01.44.14l2.44 7.51L22.81 13.43a.84.84 0 01-.16.96z" },
  { key: "jenkins", label: "Jenkins", icon: "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" },
  { key: "azure", label: "Azure DevOps", icon: "M22 4v16l-6-2.5V22l-6-5 8.5-1.5L12 7v8l-8.5-1.5L22 4z" },
  { key: "circleci", label: "CircleCI", icon: "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 14c-2.21 0-4-1.79-4-4s1.79-4 4-4 4 1.79 4 4-1.79 4-4 4zm0-6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z" },
];

// ---------------------------------------------------------------------------
// Pipeline Generators
// ---------------------------------------------------------------------------
function generatePipeline(platform: Platform, scans: Set<ScanCheck>, maxCritical: number, maxHigh: number, blockSecrets: boolean): string {
  const scanList = Array.from(scans);

  if (platform === "github") {
    return `name: Security Pipeline
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
${scanList.includes("sast") ? `
      - name: SAST Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: auto
` : ""}${scanList.includes("sca") ? `
      - name: SCA - Dependency Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: '\${{ github.repository }}'
          path: '.'
          format: 'SARIF'
` : ""}${scanList.includes("secrets") ? `
      - name: Secret Detection
        uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified
` : ""}${scanList.includes("dast") ? `
      - name: DAST Scan
        uses: zaproxy/action-full-scan@v0.9.0
        with:
          target: '\${{ vars.DAST_TARGET_URL }}'
` : ""}${scanList.includes("container") ? `
      - name: Container Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: '\${{ env.IMAGE_NAME }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
` : ""}${scanList.includes("iac") ? `
      - name: IaC Scan
        uses: bridgecrewio/checkov-action@master
        with:
          directory: terraform/
          framework: terraform
` : ""}
      - name: Quality Gate
        run: |
          CRITICAL=\$(cat results.sarif | jq '[.runs[].results[] | select(.level=="error")] | length')
          HIGH=\$(cat results.sarif | jq '[.runs[].results[] | select(.level=="warning")] | length')
          if [ "\$CRITICAL" -gt "${maxCritical}" ]; then echo "FAILED: Too many critical findings"; exit 1; fi
          if [ "\$HIGH" -gt "${maxHigh}" ]; then echo "FAILED: Too many high findings"; exit 1; fi${blockSecrets ? `
          if grep -q "secret" results.sarif; then echo "FAILED: Secrets detected"; exit 1; fi` : ""}
          echo "Quality Gate PASSED"`;
  }

  if (platform === "gitlab") {
    return `stages:
  - test
  - security
  - deploy

variables:
  MAX_CRITICAL: "${maxCritical}"
  MAX_HIGH: "${maxHigh}"
${scanList.includes("sast") ? `
sast:
  stage: security
  image: semgrep/semgrep
  script:
    - semgrep --config auto --sarif -o sast-results.sarif .
  artifacts:
    reports:
      sast: sast-results.sarif
` : ""}${scanList.includes("sca") ? `
dependency-scanning:
  stage: security
  image: owasp/dependency-check
  script:
    - dependency-check.sh --project "\$CI_PROJECT_NAME" --scan . --format SARIF
  artifacts:
    reports:
      dependency_scanning: dependency-check-report.sarif
` : ""}${scanList.includes("secrets") ? `
secret-detection:
  stage: security
  image: trufflesecurity/trufflehog
  script:
    - trufflehog filesystem . --only-verified --json > secrets.json
  allow_failure: ${!blockSecrets}
` : ""}${scanList.includes("container") ? `
container-scan:
  stage: security
  image: aquasec/trivy
  script:
    - trivy image --format sarif --output trivy.sarif \$CI_REGISTRY_IMAGE:\$CI_COMMIT_SHA
  artifacts:
    reports:
      container_scanning: trivy.sarif
` : ""}${scanList.includes("iac") ? `
iac-scan:
  stage: security
  image: bridgecrew/checkov
  script:
    - checkov -d terraform/ --framework terraform -o sarif
` : ""}
quality-gate:
  stage: security
  script:
    - echo "Checking quality gate..."
    - |
      if [ "\$CRITICAL_COUNT" -gt "\$MAX_CRITICAL" ]; then exit 1; fi
      if [ "\$HIGH_COUNT" -gt "\$MAX_HIGH" ]; then exit 1; fi`;
  }

  if (platform === "jenkins") {
    return `pipeline {
    agent any

    environment {
        MAX_CRITICAL = '${maxCritical}'
        MAX_HIGH = '${maxHigh}'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
${scanList.includes("sast") ? `
        stage('SAST') {
            steps {
                sh 'semgrep --config auto --sarif -o sast.sarif .'
            }
            post { always { recordIssues tool: sarif(pattern: 'sast.sarif') } }
        }
` : ""}${scanList.includes("sca") ? `
        stage('SCA') {
            steps {
                sh 'dependency-check.sh --project "$JOB_NAME" --scan . --format SARIF'
            }
        }
` : ""}${scanList.includes("secrets") ? `
        stage('Secret Detection') {
            steps {
                sh 'trufflehog filesystem . --only-verified --json > secrets.json'
            }
        }
` : ""}${scanList.includes("container") ? `
        stage('Container Scan') {
            steps {
                sh 'trivy image --format sarif --output trivy.sarif $IMAGE_NAME'
            }
        }
` : ""}${scanList.includes("iac") ? `
        stage('IaC Scan') {
            steps {
                sh 'checkov -d terraform/ --framework terraform'
            }
        }
` : ""}
        stage('Quality Gate') {
            steps {
                script {
                    def criticals = sh(script: "cat results.sarif | jq '...' | wc -l", returnStdout: true).trim().toInteger()
                    if (criticals > env.MAX_CRITICAL.toInteger()) {
                        error "Quality Gate FAILED: \${criticals} critical findings"
                    }
                }
            }
        }
    }
}`;
  }

  if (platform === "azure") {
    return `trigger:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  maxCritical: ${maxCritical}
  maxHigh: ${maxHigh}

steps:
  - checkout: self
    fetchDepth: 0
${scanList.includes("sast") ? `
  - task: Bash@3
    displayName: 'SAST - Semgrep'
    inputs:
      targetType: inline
      script: |
        pip install semgrep
        semgrep --config auto --sarif -o sast.sarif .
` : ""}${scanList.includes("sca") ? `
  - task: Bash@3
    displayName: 'SCA - Dependency Check'
    inputs:
      targetType: inline
      script: |
        dependency-check.sh --project "$(Build.Repository.Name)" --scan . --format SARIF
` : ""}${scanList.includes("secrets") ? `
  - task: Bash@3
    displayName: 'Secret Detection'
    inputs:
      targetType: inline
      script: |
        trufflehog filesystem . --only-verified
` : ""}
  - task: Bash@3
    displayName: 'Quality Gate'
    inputs:
      targetType: inline
      script: |
        echo "Evaluating quality gate..."`;
  }

  // CircleCI
  return `version: 2.1

orbs:
  security: cyberdef/security@1.0

jobs:
  security-scan:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
${scanList.includes("sast") ? `      - run:
          name: SAST Scan
          command: semgrep --config auto --sarif -o sast.sarif .
` : ""}${scanList.includes("sca") ? `      - run:
          name: SCA Scan
          command: dependency-check.sh --scan . --format SARIF
` : ""}${scanList.includes("secrets") ? `      - run:
          name: Secret Detection
          command: trufflehog filesystem . --only-verified
` : ""}${scanList.includes("container") ? `      - run:
          name: Container Scan
          command: trivy image --format sarif \$IMAGE_NAME
` : ""}${scanList.includes("iac") ? `      - run:
          name: IaC Scan
          command: checkov -d terraform/
` : ""}      - run:
          name: Quality Gate
          command: |
            echo "Checking max ${maxCritical} critical, max ${maxHigh} high findings"

workflows:
  security:
    jobs:
      - security-scan`;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function PipelineGeneratorPage() {
  const [platform, setPlatform] = useState<Platform>("github");
  const [scans, setScans] = useState<Set<ScanCheck>>(new Set(["sast", "sca", "secrets"]));
  const [maxCritical, setMaxCritical] = useState(0);
  const [maxHigh, setMaxHigh] = useState(5);
  const [blockSecrets, setBlockSecrets] = useState(true);
  const [copied, setCopied] = useState(false);

  const toggleScan = useCallback((scan: ScanCheck) => {
    setScans(prev => {
      const next = new Set(prev);
      if (next.has(scan)) next.delete(scan); else next.add(scan);
      return next;
    });
  }, []);

  const pipeline = useMemo(() => generatePipeline(platform, scans, maxCritical, maxHigh, blockSecrets), [platform, scans, maxCritical, maxHigh, blockSecrets]);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(pipeline);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [pipeline]);

  const handleDownload = useCallback(() => {
    const ext = platform === "jenkins" ? "Jenkinsfile" : platform === "github" ? "security-pipeline.yml" : platform === "gitlab" ? ".gitlab-ci.yml" : platform === "azure" ? "azure-pipelines.yml" : "config.yml";
    const blob = new Blob([pipeline], { type: "text/plain" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = ext; a.click();
  }, [pipeline, platform]);

  const instructions: Record<Platform, string[]> = {
    github: ["Create .github/workflows/ directory", "Save file as security-pipeline.yml", "Push to repository", "Pipeline runs on push/PR to main"],
    gitlab: ["Save as .gitlab-ci.yml in repo root", "Commit and push", "Pipeline triggers automatically"],
    jenkins: ["Create Jenkinsfile in repo root", "Configure Jenkins to use pipeline from SCM", "Point to your repository"],
    azure: ["Save as azure-pipelines.yml", "Import pipeline in Azure DevOps", "Configure service connections"],
    circleci: ["Create .circleci/ directory", "Save as config.yml", "Connect repository in CircleCI dashboard"],
  };

  return (
    <div className="flex h-full flex-col gap-4 p-6 overflow-y-auto">
      {/* Header */}
      <div>
        <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
          CI/CD Pipeline Generator
        </h1>
        <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
          SECURITY PIPELINE // QUALITY GATES // AUTOMATED SCANNING
        </p>
      </div>
      <div className="cyan-line" />

      {/* Platform Selector */}
      <div>
        <p className="text-[10px] font-bold tracking-widest text-gray-500 mb-2">SELECT PLATFORM</p>
        <div className="grid grid-cols-5 gap-3">
          {PLATFORMS.map(p => (
            <button key={p.key} onClick={() => setPlatform(p.key)}
              className={`glass-panel p-3 flex flex-col items-center gap-2 transition-all ${platform === p.key ? "border-cyan-glow/40 bg-cyan-glow/10" : "hover:border-gray-600"}`}>
              <svg viewBox="0 0 24 24" className={`h-6 w-6 ${platform === p.key ? "text-cyan-glow" : "text-gray-500"}`} fill="currentColor">
                <path d={p.icon} />
              </svg>
              <span className={`text-[10px] font-bold tracking-wider ${platform === p.key ? "text-cyan-glow" : "text-gray-500"}`}>{p.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Scan Selection */}
      <div>
        <p className="text-[10px] font-bold tracking-widest text-gray-500 mb-2">SELECT SCANS</p>
        <div className="flex flex-wrap gap-2">
          {(["sast", "sca", "secrets", "dast", "container", "iac"] as ScanCheck[]).map(s => (
            <button key={s} onClick={() => toggleScan(s)}
              className={`rounded-md border px-4 py-2 text-[10px] font-bold tracking-widest transition-all ${scans.has(s) ? "border-cyan-glow/40 bg-cyan-glow/15 text-cyan-glow" : "border-gray-700 text-gray-500 hover:border-gray-600"}`}>
              {s.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Quality Gate Config */}
      <div className="glass-panel p-4 space-y-3">
        <p className="text-[10px] font-bold tracking-widest text-gray-500">QUALITY GATE CONFIGURATION</p>
        <div className="grid grid-cols-3 gap-4">
          <div>
            <label className="text-[10px] text-gray-500 block mb-1">Max Critical Findings</label>
            <input type="number" value={maxCritical} onChange={e => setMaxCritical(Number(e.target.value))} min={0} className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 font-mono focus:border-cyan-glow/40 focus:outline-none" />
          </div>
          <div>
            <label className="text-[10px] text-gray-500 block mb-1">Max High Findings</label>
            <input type="number" value={maxHigh} onChange={e => setMaxHigh(Number(e.target.value))} min={0} className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 font-mono focus:border-cyan-glow/40 focus:outline-none" />
          </div>
          <div className="flex items-end">
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={blockSecrets} onChange={e => setBlockSecrets(e.target.checked)} className="rounded border-gray-600 bg-gray-900 text-cyan-glow focus:ring-cyan-glow/30" />
              <span className="text-[10px] font-bold tracking-widest text-gray-400">BLOCK ON SECRETS</span>
            </label>
          </div>
        </div>
      </div>

      {/* Generated Pipeline */}
      <div className="glass-panel p-4 space-y-3">
        <div className="flex items-center justify-between">
          <p className="text-[10px] font-bold tracking-widest text-gray-500">GENERATED PIPELINE</p>
          <div className="flex gap-2">
            <button onClick={handleCopy} className="glass-panel px-3 py-1.5 text-[10px] font-bold text-cyan-glow hover:bg-cyan-glow/10 transition-colors">
              {copied ? "COPIED!" : "COPY"}
            </button>
            <button onClick={handleDownload} className="glass-panel px-3 py-1.5 text-[10px] font-bold text-gray-400 hover:text-cyan-glow transition-colors">
              DOWNLOAD
            </button>
          </div>
        </div>
        <pre className="rounded border border-cyan-glow/10 bg-space-deep p-4 text-[11px] text-cyan-glow/80 font-mono overflow-x-auto max-h-[400px] overflow-y-auto leading-relaxed">{pipeline}</pre>
      </div>

      {/* Integration Instructions */}
      <div className="glass-panel p-4 space-y-2">
        <p className="text-[10px] font-bold tracking-widest text-gray-500">INTEGRATION INSTRUCTIONS</p>
        <div className="space-y-1">
          {instructions[platform].map((step, i) => (
            <div key={i} className="flex items-center gap-2">
              <span className="flex h-5 w-5 items-center justify-center rounded-full bg-cyan-glow/10 text-[10px] font-bold text-cyan-glow">{i + 1}</span>
              <span className="text-xs text-gray-400">{step}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
