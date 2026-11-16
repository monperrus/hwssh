# Test server: hardened sshd + hwssh registry. Build context is the repo root.
FROM ubuntu:24.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server python3 python3-venv \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && rm -f /etc/ssh/ssh_host_* && ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
COPY pyproject.toml README.md LICENSE /src/
COPY hwssh /src/hwssh
RUN python3 -m venv /opt/hwssh && /opt/hwssh/bin/pip install -q /src \
 && printf '#!/bin/sh\nexec /opt/hwssh/bin/hwssh "$@"\n' > /usr/local/bin/hwssh \
 && chmod 755 /usr/local/bin/hwssh
COPY config/sshd_config /etc/ssh/sshd_config
# alice has a password and a plain key in ~/.ssh/authorized_keys: both must be refused.
RUN useradd -m -s /bin/bash alice && echo 'alice:hunter2' | chpasswd \
 && mkdir -p /etc/hwssh/registry
COPY tests/e2e/registry/ /etc/hwssh/registry/
COPY tests/e2e/plain_authorized_keys /home/alice/.ssh/authorized_keys
RUN chown -R alice /home/alice/.ssh && chmod -R a+rX,go-w /etc/hwssh && sshd -t
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
