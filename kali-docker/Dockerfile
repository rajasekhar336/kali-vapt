# syntax=docker/dockerfile:1.6

# =========================================================
# Kali Linux VAPT Image
# =========================================================
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# -------------------------------
# Install Kali tools and dependencies
# -------------------------------
RUN apt-get update && apt-get install -y \
    # Core tools available in Kali
    amass subfinder assetfinder naabu nmap nuclei \
    feroxbuster gobuster ffuf dirsearch \
    whatweb nikto dnsrecon sslscan wpscan \
    joomscan skipfish \
    sqlmap metagoofil \
    # Additional tools available in Kali
    masscan dirb dnsenum fierce sublist3r dnsx \
    wapiti enum4linux smbmap samba-common \
    # Python tools
    python3 python3-venv python3-pip pipx golang-go \
    # Additional tools
    git curl wget jq \
    && rm -rf /var/lib/apt/lists/*

# -------------------------------
# Install additional Python tools
# -------------------------------
RUN pip install --break-system-packages pipx && \
    pipx install dirsearch && \
    pipx install shodan && \
    pipx install sslyze && \
    pipx ensurepath && \
    ln -sf /root/.local/bin/sslyze /usr/local/bin/sslyze

# -------------------------------
# Install Go tools
# -------------------------------
ENV GOPATH=/root/go
ENV PATH=$PATH:/root/go/bin:/usr/local/bin
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/hakluke/hakrawler@latest && \
    go install github.com/jaeles-project/gospider@latest && \
    go install github.com/michenriksen/aquatone@latest && \
    go install github.com/RustScan/RustScan@latest && \
    cp /root/go/bin/* /usr/local/bin/ 2>/dev/null || true

# -------------------------------
# Install exploitdb
# -------------------------------
RUN git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && \
    chmod +x /opt/exploitdb/searchsploit && \
    ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit && \
    rm -rf /opt/exploitdb/.git

# -------------------------------
# Install git-based tools
# -------------------------------
RUN git clone https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl && \
    rm -rf /opt/testssl/.git

# Install droopescan via pip
RUN pip install --break-system-packages droopescan

# Install sublist3r via pip
RUN pip install --break-system-packages Sublist3r

# Install hakrawler via Go
RUN go install github.com/hakluke/hakrawler@latest && \
    mv /root/go/bin/hakrawler /usr/local/bin/ 2>/dev/null || true

# Install gospider via Go
RUN go install github.com/jaeles-project/gospider@latest && \
    mv /root/go/bin/gospider /usr/local/bin/ 2>/dev/null || true

# Install aquatone via Go
RUN go install github.com/michenriksen/aquatone@latest && \
    mv /root/go/bin/aquatone /usr/local/bin/ 2>/dev/null || true

# -------------------------------
# Create user and setup
# -------------------------------
RUN useradd -m -s /bin/bash pentester && \
    mkdir -p /opt/work && \
    chown -R pentester:pentester /opt

USER pentester
WORKDIR /opt/work

# -------------------------------
# Set PATH
# -------------------------------
ENV PATH=$PATH:/usr/local/bin

CMD ["/bin/bash"]
