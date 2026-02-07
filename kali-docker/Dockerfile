FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV GO111MODULE=on
ENV PATH="/root/go/bin:${PATH}"

# -----------------------------
# System + Dev Dependencies
# -----------------------------
RUN apt-get update && apt-get install -y \
    git curl wget unzip jq \
    python3 python3-pip python3-venv \
    golang-go \
    build-essential \
    libpcap-dev \
    libssl-dev \
    libffi-dev \
    libxml2-dev libxslt1-dev \
    zlib1g-dev \
    nmap \
    nikto \
    whatweb \
    dnsutils \
    net-tools \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y python3-pip python3-venv pipx && \
    pipx ensurepath && \
    pipx install wafw00f && \
    pipx install uro && \
    pipx install arjun && \
    pipx install xsrfprobe

# -----------------------------
# Install Go Tools (Latest)
# -----------------------------
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install github.com/lc/gau/v2/cmd/gau@latest
RUN go install github.com/tomnomnom/waybackurls@latest
RUN go install github.com/tomnomnom/assetfinder@latest
RUN go install github.com/ffuf/ffuf@latest

# -----------------------------
# Dirsearch
# -----------------------------
RUN git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch \
    && rm -rf /opt/dirsearch/.git

# -----------------------------
# SecLists (wordlists)
# -----------------------------
RUN git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists \
    && rm -rf /opt/SecLists/.git

# -----------------------------
# testssl.sh
# -----------------------------
RUN git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && rm -rf /opt/testssl.sh/.git \
    && chmod +x /opt/testssl.sh/testssl.sh

# -----------------------------
# Nuclei Templates
# -----------------------------
RUN nuclei -update-templates

# -----------------------------
# Create Working Directory
# -----------------------------
WORKDIR /scanner

# Default command
CMD ["/bin/bash"]
