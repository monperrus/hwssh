FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server faketime \
 && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd && rm -f /etc/ssh/ssh_host_* \
 && ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key && useradd -m alice && usermod -p '*' alice
RUN printf 'HostKey /etc/ssh/ssh_host_ed25519_key\nAuthorizedKeysFile none\nTrustedUserCAKeys /etc/ssh/ca.pub\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n' > /etc/ssh/sshd_config
CMD ["/usr/sbin/sshd", "-D", "-e"]
