# ECP Aegis — Phase 1 Sandbox Lab

A fully-isolated, simulated infrastructure lab on macOS (Apple Silicon) for validating the **ECP Aegis**
AI-driven pentest stack **before any live ECP system is touched**. Plan: `../ECP_Network.../ECP_Aegis_Pentest_Plan.md`.

> ⚠️ Authorized internal security testing only. The target lab is intentionally vulnerable — keep it isolated.

## What's here
```
targets/   vulnerable-host lab (Juice Shop, DVWA, Samba, Kali attacker) on an internal-only docker net
frrlab/    simulated 2-router OSPF network (FRR, native arm64) for containerlab inside an OrbStack VM
scripts/   verify-isolation.sh — proves the lab can't reach the real LAN/internet
pentagi/   PentAGI .env notes for arm64 + local Ollama + two-node isolation
```

## Quick start

### A. Vulnerable target lab (Docker Desktop, native arm64)
```bash
cd targets
docker compose up -d
# verify isolation FIRST (set your real LAN gateway):
LAN_GW=192.168.1.1 ../scripts/verify-isolation.sh
# attack from inside the lab:
docker compose exec attacker bash    # then: nmap -sV 172.30.0.0/24
```
Targets: Juice Shop `172.30.0.10:3000` · DVWA `172.30.0.11:80` · Samba `172.30.0.12:445`.

### B. Simulated network (FRR) — inside an OrbStack arm64 Linux VM
```bash
# in the Linux VM:
bash -c "$(curl -sL https://get.containerlab.dev)"
cd frrlab
sudo containerlab deploy -t frrlab.clab.yml
docker exec -it clab-frrlab-r1 vtysh -c "show ip ospf neighbor"   # expect r2 adjacency
```

### C. PentAGI orchestrator
See `pentagi/env.notes.md`.

## Safety invariants (must hold before any live work)
1. `verify-isolation.sh` passes: lab peer reachable; host LAN + internet + DNS blocked; no default route.
2. `targets/scope-policy.yaml` `allowed_cidrs` == the docker `--subnet` (lab `/24` only).
3. Tool firewall `default: deny`; dangerous tools `armed_only`.
4. HMAC audit key (`PENTEST_AUDIT_HMAC_KEY`) injected into the wrapper, never the container.
5. Local Ollama for anything resembling live data; cloud LLM for offline reporting only.

## Teardown
```bash
cd targets && docker compose down
cd ../frrlab && sudo containerlab destroy -t frrlab.clab.yml
```
