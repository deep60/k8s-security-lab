# Kubernetes Security Hardening — Lab Report

## Cluster Setup
- Tool: kind (multinode — 1 control plane, 2 workers)
- Kubernetes version: v1.36.1
- Platform: macOS (Apple Silicon)

## 1. RBAC
- Created 3 namespaces: frontend, backend, restricted
- Developer role: read-only access to pods/deployments in frontend namespace
- Deliberately misconfigured: frontend default ServiceAccount given cluster-admin (CVE simulation)
- Audit script identified 3 cluster-admin bindings including overprivileged-binding

## 2. OPA Gatekeeper — Policy Enforcement
| Policy | Result |
|--------|--------|
| Privileged pod blocked | PASS — admission webhook denied request |
| Normal pod allowed | PASS — created successfully |
| Registry restriction (restricted ns) | PASS — non-whitelisted images blocked |

## 3. Network Policies
| Test | Expected | Result |
|------|----------|--------|
| frontend → backend | ALLOWED | PASS |
| restricted → backend | BLOCKED | PASS (timeout) |

Default-deny-all applied to backend and restricted namespaces.

## 4. Falco — Runtime Detection
- Installed via Helm with modern_ebpf driver
- Custom rules loaded and schema validated:
  - Sensitive file read detection
  - Crypto mining process detection
  - Shell spawned in container
- Note: Syscall-level detection limited on macOS/kind due to Linux kernel dependency
- Rules validated via: /etc/falco/rules.d/custom-rules.yaml | schema validation: ok

## 5. CIS Benchmark — kube-bench
| Metric | Before Hardening | After Hardening |
|--------|-----------------|-----------------|
| PASS   | 17              | 19              |
| FAIL   | 2               | 0               |
| WARN   | 40              | 40              |

### Fixes Applied
- 4.1.1: kubelet service file permissions → chmod 600
- 4.1.9: kubelet config.yaml permissions → chmod 600

## 6. Attack Simulations
| Attack | Defense Layer | Result |
|--------|--------------|--------|
| Privileged container deploy | OPA Gatekeeper | BLOCKED |
| Cross-namespace traffic (restricted→backend) | Network Policy | BLOCKED |
| Overprivileged ServiceAccount | RBAC audit script | DETECTED |

## Known Limitations
- Falco syscall detection requires Linux kernel — not fully testable on macOS/kind
- WARN checks (40) are production-specific, not applicable to local kind cluster
