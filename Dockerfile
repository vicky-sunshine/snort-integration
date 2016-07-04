FROM linton/docker-ryu

MAINTAINER John Lin <linton.tw@gmail.com>

ENV HOME /root
# Define working directory for download source.
WORKDIR /root

# Download snort-integration source
RUN curl -kL https://github.com/hsnl-dev/snort-integration/archive/master.tar.gz | tar -xvz

# Define working directory for running ryu-manager
WORKDIR /root/snort-integration-master

EXPOSE 8080 6633

CMD ["ryu-manager", "one_host_version/network_tap.py", "one_host_version/snort_firewall.py"]
