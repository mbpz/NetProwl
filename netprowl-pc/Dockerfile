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
RUN apt-get update && apt-get install -y --no-install-recommends \
    libwebkit2gtk-4.1-0 libappindicator3-1 librsvg2-4.1 curl \
    && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y --no-install-recommends \
    masscan nmap \
    && curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip -o /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /var/lib/apt/lists/*
COPY --from=frontend-builder /app/dist /app/dist
COPY --from=tauri-builder /app/src-tauri/target/release/netprowl-pc /app/netprowl-pc
COPY install.sh /app/install.sh
RUN chmod +x /app/install.sh
ENV PATH="/app:${PATH}"
CMD ["/app/netprowl-pc"]