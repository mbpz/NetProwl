# Docker Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** NetProwl PC 版加 Docker 支持，参考 hackingtool 的 `docker build + compose` 模式。

**Architecture:** 单一 Dockerfile 构建 + docker-compose 管理，支持 dev profile 挂载源码。

---

## Task 1: Dockerfile

**Files:**
- Create: `netprowl-pc/Dockerfile`

- [ ] **Step 1: Write Dockerfile**

```dockerfile
FROM node:20-alpine AS frontend-builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM rust:1.75-bookworm AS tauri-builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src-tauri/Cargo.toml src-tauri/Cargo.lock ./
RUN mkdir -p src-tauri/src
COPY src-tauri/src/ src-tauri/src/
RUN cargo build --release --manifest-path src-tauri/Cargo.toml

FROM debian:bookworm-slim
WORKDIR /app
# Install runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libwebkit2gtk-4.1-0 libappindicator3-1 librsvg2-4.1 curl \
    && rm -rf /var/lib/apt/lists/*
# Install security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    masscan nmap \
    && curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.0/nuclei_linux_amd64.zip -o /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /var/lib/apt/lists/*
# Copy built assets
COPY --from=frontend-builder /app/dist /app/dist
COPY --from=tauri-builder /app/src-tauri/target/release/netprowl-pc /app/netprowl-pc
COPY install.sh /app/install.sh
RUN chmod +x /app/install.sh
ENV PATH="/app:${PATH}"
CMD ["/app/netprowl-pc"]
```

- [ ] **Step 2: Verify docker build syntax**

`docker build -t netprowl-pc -f netprowl-pc/Dockerfile netprowl-pc 2>&1 | tail -10`

- [ ] **Step 3: Commit**

```bash
git add netprowl-pc/Dockerfile && git commit -m "feat(pc): add Dockerfile for containerized build"
```

---

## Task 2: docker-compose.yml

**Files:**
- Create: `netprowl-pc/docker-compose.yml`

- [ ] **Step 1: Write docker-compose.yml**

```yaml
services:
  netprowl:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: netprowl-pc
    environment:
      - DISPLAY=${DISPLAY}
    volumes:
      - /tmp/.X11-unix:/tmp/.X11-unix:rw
      - netprowl-data:/app/data
    network_mode: host
   privileged: true
    profiles:
      - default

  netprowl-dev:
    build:
      context: .
      dockerfile: Dockerfile.dev
    container_name: netprowl-pc-dev
    environment:
      - DISPLAY=${DISPLAY}
    volumes:
      - .:/app:rw
      - /tmp/.X11-unix:/tmp/.X11-unix:rw
    network_mode: host
    privileged: true
    profiles:
      - dev

volumes:
  netprowl-data:
```

- [ ] **Step 2: Commit**

```bash
git add netprowl-pc/docker-compose.yml && git commit -m "feat(pc): add docker-compose.yml with dev profile"
```

---

## Self-Review

1. **Spec coverage**: Dockerfile ✓, docker-compose ✓, dev profile ✓
2. **Placeholder scan**: no TBD/TODO
3. Type consistency: profiles use correct docker compose syntax

---

Plan saved to `docs/superpowers/plans/2026-05-12-docker-support-plan.md`.
