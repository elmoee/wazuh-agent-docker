FROM phusion/baseimage:focal-1.0.0

# Use baseimage-docker's init system.
CMD ["/sbin/my_init"]

RUN apt update
RUN apt install -y gnupg curl

# wazuh
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
RUN echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

# rsyslog
RUN add-apt-repository ppa:adiscon/v8-devel

# osquery
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
RUN add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'

RUN apt update
RUN apt install -y rsyslog osquery wazuh-agent
RUN echo "wazuh-agent hold" | dpkg --set-selections

RUN mkdir -p /etc/my_init.d
COPY wazuhd.sh /etc/my_init.d/wazuhd.sh
RUN chmod +x /etc/my_init.d/wazuhd.sh

# Clean up APT when done.
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*