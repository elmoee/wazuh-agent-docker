FROM phusion/baseimage:focal-1.0.0

# Use baseimage-docker's init system.
CMD ["/sbin/my_init"]

RUN rm -f /etc/service/sshd/down

# Regenerate SSH host keys. baseimage-docker does not contain any, so you
# have to do that yourself. You may also comment out this instruction; the
# init system will auto-generate one during boot.
RUN /etc/my_init.d/00_regen_ssh_host_keys.sh

RUN apt update
RUN apt install -y gnupg curl

# wazuh
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
RUN echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

RUN apt update
RUN apt install -y wazuh-agent
RUN echo "wazuh-agent hold" | dpkg --set-selections

RUN mkdir -p /etc/my_init.d

COPY wazuhd.sh /etc/my_init.d/wazuhd.sh
RUN chmod +x /etc/my_init.d/wazuhd.sh

# authorize SSH connection with root account
RUN sed -i 's/^#.*PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN service ssh restart

# change password root
RUN echo "root:root" | chpasswd

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*