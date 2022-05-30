FROM centos:centos7.4.1708

RUN yum -y groupinstall "Development Tools"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN cp ~/.cargo/bin/cargo /usr/bin/cargo
