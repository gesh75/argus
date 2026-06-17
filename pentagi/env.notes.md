# PentAGI bring-up on Apple Silicon — .env notes

```bash
# Single-host bring-up (pulls native arm64 images, no emulation)
curl -o .env https://raw.githubusercontent.com/vxcontrol/pentagi/master/.env.example
curl -O https://raw.githubusercontent.com/vxcontrol/pentagi/master/docker-compose.yml
docker compose up -d
# UI: https://localhost:8443   login: admin@pentagi.com / admin  (CHANGE IMMEDIATELY)

# Confirm the worker image is arm64-native (expect linux/arm64):
docker image inspect vxcontrol/kali-linux --format '{{.Os}}/{{.Architecture}}'
```

## Key .env settings — local LLM (PHI-safe) + arm64 worker
```
DOCKER_DEFAULT_IMAGE=debian:latest
DOCKER_DEFAULT_IMAGE_FOR_PENTEST=vxcontrol/kali-linux   # multi-arch -> arm64 on M-series
OLLAMA_SERVER_URL=http://host.docker.internal:11434     # run `ollama serve` on the Mac HOST (Metal GPU)
OLLAMA_SERVER_MODEL=llama3.1:8b
OLLAMA_SERVER_PULL_MODELS_ENABLED=true
OLLAMA_SERVER_LOAD_MODELS_ENABLED=true
```
Cloud Claude (offline reporting only) = just add ANTHROPIC API key to .env.

## Two-node isolation (recommended for live phases)
Run control plane on the Mac, offensive Kali workers on a SEPARATE disposable Docker host:
```
DOCKER_INSIDE=true
DOCKER_SOCKET=tcp://WORKER_HOST_IP:2376    # use TLS certs in production
```

## Gotchas
- Run Ollama on the HOST, not in a container (no GPU passthrough in a Linux arm64 container).
- Docker Desktop → Settings → enable "Allow default Docker socket" or worker-spawn fails.
- Give Docker Desktop ≥ 8 GB RAM / 4 CPU (2 vCPU / 1 GB "minimum" excludes Kali worker + Ollama).
- 8443/443 port collisions: remap if a host service already binds them.
```
