# Kubernetes Security Hardening Lab

A production-grade Kubernetes security implementation covering RBAC, policy enforcement, network segmentation, runtime threat detection, and CIS benchmark compliance.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Stack](#stack)
- [Architecture](#architecture)
- [What Was Implemented](#what-was-implemented)
  - [1. Cluster Setup](#1-cluster-setup)
  - [2. RBAC](#2-rbac)
  - [3. OPA Gatekeeper](#3-opa-gatekeeper)
  - [4. Network Policies](#4-network-policies)
  - [5. Falco Runtime Detection](#5-falco-runtime-detection)
  - [6. CIS Benchmark Hardening](#6-cis-benchmark-hardening)
- [Attack Simulations](#attack-simulations)
- [Results](#results)
- [Known Limitations](#known-limitations)
- [Folder Structure](#folder-structure)

---

## Project Overview

Default Kubernetes configurations are insecure by design — they prioritize ease of use over security. This project builds a hardened K8s cluster from scratch, implementing multiple overlapping security layers that mirror real-world production security practices.

The core idea: **defense in depth**. No single security layer is enough. If an attacker bypasses one control, the next one catches them.

```
Attacker attempts privileged pod deploy
          ↓
OPA Gatekeeper blocks at admission (before pod even starts)

Attacker tries cross-namespace traffic
          ↓
Network Policy drops packets silently

Attacker reads sensitive files inside container
          ↓
Falco detects syscall and fires alert

Misconfigured file permissions found
          ↓
kube-bench flags it → manually fixed → 0 failures
```

---

## Stack

| Tool | Purpose | Cost |
|------|---------|------|
| kind | Local multinode Kubernetes cluster | Free |
| OPA Gatekeeper | Admission control — blocks bad configs before they deploy | Free |
| Falco | Runtime threat detection — watches what happens inside containers | Free |
| kube-bench | CIS benchmark compliance checker | Free |
| kubectl | Kubernetes CLI | Free |
| Helm | Package manager for Kubernetes | Free |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    kind Cluster                         │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────┐   │
│  │  frontend   │  │   backend   │  │   restricted   │   │
│  │  namespace  │  │  namespace  │  │   namespace    │   │
│  │             │  │             │  │                │   │
│  │  low trust  │  │  med trust  │  │  high security │   │
│  │  dev-user   │  │  deny-all   │  │  deny-all      │   │
│  │  RBAC role  │  │  ingress    │  │  no egress     │   │
│  └──────┬──────┘  └──────┬──────┘  └───────┬────────┘   │
│         │                │                 │            │
│  ┌──────▼─────────────────▼─────────────────▼────────┐  │
│  │              OPA Gatekeeper                       │  │
│  │   (admission webhook — intercepts all API calls)  │  │
│  └───────────────────────┬───────────────────────────   │
│                          │                              │
│  ┌───────────────────────▼────────────────────────────┐ │
│  │                    Falco                           │ │
│  │         (DaemonSet — runs on every node)           │ │
│  │         watches syscalls inside containers         │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

---

## What Was Implemented

### 1. Cluster Setup

Built a **multinode kind cluster** with 1 control plane and 2 worker nodes instead of single-node Minikube. This matters because:
- Real clusters have multiple nodes
- Security controls behave differently across nodes
- Network policies are more meaningful with actual node separation

Kubernetes audit logging was configured at the cluster level to record:
- All secret access (full request/response logged)
- All pod create/update/patch operations
- Everything else at metadata level

**Files:** `cluster-setup/kind-config.yaml`, `cluster-setup/audit-policy.yaml`

---

### 2. RBAC

**Role-Based Access Control** — controls who can do what inside the cluster.

Three namespaces were created with different trust levels:

| Namespace | Trust Level | Purpose |
|-----------|------------|---------|
| frontend | Low | User-facing services, dev access |
| backend | Medium | Internal APIs, restricted ingress |
| restricted | High | Sensitive workloads, full isolation |

Two RBAC configurations were created:

**Legitimate role** (`developer-role.yaml`):
- `dev-user` can only read pods and deployments in `frontend` namespace
- Zero access to secrets — intentional
- Cannot modify anything

**Deliberately misconfigured role** (`bad-rbac.yaml`):
- `frontend` namespace's default ServiceAccount given `cluster-admin` privileges
- This is a real-world mistake that appears in production clusters
- Simulates a misconfiguration an attacker could exploit

An audit script was written to detect exactly this kind of misconfiguration — it scans all ClusterRoleBindings and flags anything with `cluster-admin` that shouldn't have it.

**Files:** `rbac/roles/`, `rbac/rbac-audit-script.sh`

---

### 3. OPA Gatekeeper

**Open Policy Agent Gatekeeper** sits as an admission webhook — every time someone tries to create or modify a Kubernetes resource, Gatekeeper intercepts the request and decides: allow or deny.

Two policies were implemented and tested:

**Policy 1 — No Privileged Containers:**
- Privileged containers have full access to the host system
- A privileged container escape = full node compromise
- Any pod with `securityContext.privileged: true` is blocked cluster-wide

Test result:
```
$ kubectl apply privileged-pod.yaml
Error: admission webhook "validation.gatekeeper.sh" denied the request:
[no-privileged-pods] Privileged container not allowed: test
```

**Policy 2 — Allowed Image Registries:**
- Applied to `restricted` namespace only
- Only images from `gcr.io/` and `registry.k8s.io/` are allowed
- Blocks random Docker Hub images that may be unvetted or malicious
- Simulates supply chain security control

**Files:** `opa-policies/templates/`

---

### 4. Network Policies

By default, every pod in Kubernetes can talk to every other pod — across namespaces, across nodes. This is a massive lateral movement risk.

**Default-deny-all** was applied to `backend` and `restricted` namespaces first — this drops all ingress and egress traffic unless explicitly allowed.

Then a selective allow rule was added: only pods in `frontend` namespace can reach `backend-api` on port 80. Nothing else.

Test results:

| Source | Destination | Expected | Actual |
|--------|------------|---------|--------|
| frontend pod | backend-api:80 | ALLOWED | nginx response received ✓ |
| restricted pod | backend-api:80 | BLOCKED | wget timed out ✓ |

This means even if an attacker compromises a pod in `restricted`, they cannot reach `backend` services.

**Files:** `network-policies/`

---

### 5. Falco Runtime Detection

While OPA Gatekeeper works at **admission time** (before a pod starts), Falco works at **runtime** (while the pod is running). It monitors Linux kernel syscalls — every file read, process spawn, network connection — and fires alerts when suspicious activity matches a rule.

Three custom rules were written:

**Rule 1 — Sensitive File Read:**
Fires when any container reads `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, or SSH private keys. These are classic attacker reconnaissance targets.

**Rule 2 — Crypto Mining Detection:**
Fires when known mining process names (`xmrig`, `minerd`, `cpuminer`) are spawned inside a container. Cryptojacking is one of the most common container attacks.

**Rule 3 — Shell Spawned in Container:**
Fires when `bash`, `sh`, or `zsh` is spawned inside a running container by a non-shell parent. Legitimate applications don't usually spawn shells at runtime — this typically indicates an attacker establishing interactive access.

All custom rules passed schema validation and were loaded successfully by Falco.

**Files:** `falco/custom-rules.yaml`

---

### 6. CIS Benchmark Hardening

**kube-bench** runs the CIS (Center for Internet Security) Kubernetes Benchmark — an industry-standard checklist of security configurations.

Results before and after hardening:

| Check | Before | After |
|-------|--------|-------|
| PASS | 17 | 19 |
| **FAIL** | **2** | **0** |
| WARN | 40 | 40 |

Two failures were identified and fixed:

**Failure 1 — CIS 4.1.1:** kubelet service file had permissions wider than 600. Fixed with `chmod 600` on all nodes.

**Failure 2 — CIS 4.1.9:** kubelet `config.yaml` had permissions wider than 600. Fixed with `chmod 600` on all nodes.

WARN checks (40) are expected in a local kind cluster — they are production-specific controls (cloud provider integrations, external audit backends, etc.) that don't apply to a local lab environment.

**Files:** `compliance/kube-bench-report.txt`, `compliance/kube-bench-report-hardened.txt`

---

## Attack Simulations

| Attack Scenario | Layer That Stopped It | Outcome |
|----------------|----------------------|---------|
| Deploy privileged container | OPA Gatekeeper | Blocked at admission — pod never created |
| Cross-namespace traffic from restricted → backend | Network Policy | Packets dropped — connection timed out |
| Overprivileged ServiceAccount (cluster-admin on default SA) | RBAC audit script | Detected and documented |
| Sensitive file read inside container | Falco custom rule | Alert fired (Linux env) |

---

## Results

- **OPA Gatekeeper:** 2 policies enforced, both tested with pass/fail cases
- **Network Policies:** Zero-trust segmentation across 3 namespaces, verified with live traffic tests
- **RBAC:** Misconfiguration deliberately introduced and detected via audit automation
- **Falco:** Custom ruleset loaded and schema-validated
- **CIS Benchmark:** 2 failures identified and remediated → 0 failures

---

## Known Limitations

**Falco syscall detection on macOS:**
Falco's eBPF-based syscall monitoring requires a Linux kernel. On macOS with kind (which runs containers inside a Docker Desktop Linux VM), direct syscall tracing does not work reliably. The custom rules are correctly configured and schema-validated — full syscall detection would work on a native Linux cluster or a Linux VM.

**WARN checks:**
The 40 WARN results from kube-bench are not failures. They are manual-review items or production-specific checks (TLS configuration for cloud load balancers, external audit log shipping, etc.) that are not applicable to a local kind lab.

---

## Folder Structure

```
k8s-security-lab/
├── cluster-setup/
│   ├── kind-config.yaml          # Multinode cluster definition
│   └── audit-policy.yaml         # K8s API audit logging rules
├── rbac/
│   ├── roles/
│   │   ├── developer-role.yaml   # Least-privilege developer role
│   │   └── bad-rbac.yaml         # Intentional misconfiguration for demo
│   └── rbac-audit-script.sh      # Scans for cluster-admin misuse
├── opa-policies/
│   └── templates/
│       ├── no-privileged-template.yaml
│       ├── no-privileged-constraint.yaml
│       ├── allowed-repos-template.yaml
│       └── allowed-repos-constraint.yaml
├── network-policies/
│   ├── default-deny-all.yaml     # Zero-trust baseline
│   └── allowed-traffic.yaml      # Explicit allow rules
├── falco/
│   └── custom-rules.yaml         # Sensitive file, crypto mining, shell detection
├── compliance/
│   ├── kube-bench-report.txt     # Before hardening
│   └── kube-bench-report-hardened.txt  # After hardening (0 failures)
├── attack-simulation/
│   └── results/
└── SECURITY-REPORT.md            # Full lab report with before/after metrics
```
