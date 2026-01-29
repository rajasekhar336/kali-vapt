# syntax=docker/dockerfile:1.6

# =========================================================
# Stage 1: Builder
# =========================================================
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/opt/go
ENV PATH=$PATH:/opt/go/bin

# -------------------------------
# Build dependencies
# -------------------------------
RUN apt-get update && apt-get install -y \
    build-essential \
    curl wget git unzip \
    golang-go \
    python3 python3-venv python3-dev \
    pip \
    libpcap-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# -------------------------------
# Go-based tools (cached = fast)
# -------------------------------
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go install github.com/owasp-amass/amass/v3/...@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest



# Strip Go binaries (smaller)
RUN strip /opt/go/bin/* || true

# -------------------------------
# Clone script-based tools (no .git)
# -------------------------------
RUN git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    git clone https://github.com/laramies/metagoofil.git /opt/metagoofil && \
    git clone https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists && \
    rm -rf \
      /opt/sqlmap/.git \
      /opt/metagoofil/.git \
      /opt/testssl/.git \
      /opt/SecLists/.git

# -------------------------------
# RustScan
# -------------------------------
RUN curl -L https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb \
    -o /tmp/rustscan.deb

# =========================================================
# Stage 2: Runtime
# =========================================================
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH=$PATH:/opt/tools/bin:/home/pentester/.local/bin

# -------------------------------
# Runtime dependencies only
# -------------------------------
RUN apt-get update && apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    git \
    curl \
    libpcap0.8 \
    nmap masscan netcat-openbsd dnsutils whois jq \
    wapiti \
    ffuf gobuster nikto whatweb dnsrecon sslscan \
    ruby-full \
    ca-certificates \
    util-linux \
    libxml2-utils \
    && rm -rf /var/lib/apt/lists/*

# Remove docs/locales (shrink image)
RUN rm -rf /usr/share/doc/* /usr/share/man/* /usr/share/locale/*

# -------------------------------
# Filesystem layout (Kali-style)
# -------------------------------
RUN mkdir -p \
    /opt/tools/bin \
    /opt/tools/sqlmap \
    /opt/tools/metagoofil \
    /opt/tools/testssl \
    /opt/wordlists \
    /opt/work

# -------------------------------
# Copy from builder
# -------------------------------
COPY --from=builder /opt/go/bin/* /opt/tools/bin/
COPY --from=builder /opt/sqlmap /opt/tools/sqlmap
COPY --from=builder /opt/metagoofil /opt/tools/metagoofil
COPY --from=builder /opt/testssl /opt/tools/testssl
COPY --from=builder /opt/SecLists /opt/wordlists/SecLists
COPY --from=builder /tmp/rustscan.deb /tmp/rustscan.deb

RUN dpkg -i /tmp/rustscan.deb && rm /tmp/rustscan.deb
RUN git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && chmod +x /opt/exploitdb/searchsploit && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# -------------------------------
# Non-root user
# -------------------------------
RUN useradd -m -s /bin/bash pentester && \
    chown -R pentester:pentester /opt

USER pentester
WORKDIR /opt/work

# -------------------------------
# Install Python tools with pipx
# -------------------------------
RUN pip install --break-system-packages pipx && \
    pipx install git+https://github.com/laramies/theHarvester.git && \
    pipx install dirsearch && \
    pipx inject dirsearch setuptools && \
    pipx install shodan && \
    pipx inject shodan setuptools && \
    pipx install sslyze 

CMD ["/bin/bash"]
