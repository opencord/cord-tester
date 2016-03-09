FROM ubuntu
MAINTAINER chetan@ciena.com

LABEL RUN docker pull ubuntu:14.04
LABEL RUN docker run -it --name nosetest ubuntu:14.04

RUN apt-get update 
RUN apt-get -y install git python python-pip python-setuptools python-scapy tcpdump doxygen doxypy
RUN easy_install nose
RUN apt-get -y install openvswitch-common openvswitch-switch
WORKDIR /root
RUN mkdir ovs
COPY ./openvswitch-2.4.0.tar.gz /root
COPY ./build_ovs.sh /root/
RUN /root/build_ovs.sh
RUN apt-get -y install python-twisted
RUN pip install scapy-ssl_tls
RUN pip install monotonic
RUN mv /usr/sbin/tcpdump /sbin/
RUN ln -sf /sbin/tcpdump /usr/sbin/tcpdump
CMD ["/bin/bash"]
