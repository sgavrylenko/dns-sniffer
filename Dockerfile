FROM centos:7

RUN yum update -y
RUN yum -y install vim wget
RUN yum install -y libpcap-devel gcc-go
RUN wget https://storage.googleapis.com/golang/getgo/installer_linux \
        && chmod +x ./installer_linux \
        && SHELL=/bin/bash ./installer_linux -v \
        && source /root/.bash_profile
