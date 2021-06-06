FROM ubuntu:20.04
ARG DEBIAN_FRONTEND=noninteractive

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get install -y \
        aptitude \
        autoconf \
        automake \
        binutils \
        bison \
        bridge-utils \
        build-essential \
        ca-certificates \
        cmake \
        curl \
        flex \
        gdb \
        git \
        gpg \
        install-info \
        iproute2 \
        iputils-ping \
        less \
        libc-ares-dev \
        libcap-dev \
        libelf-dev \
        libgrpc++-dev \
        libgrpc-dev \
        libjson-c-dev \
        liblua5.3-dev \
        libpam0g-dev \
        libpcre2-dev \
        libpython3-dev \
        libreadline-dev \
        libsnmp-dev \
        libsystemd-dev \
        libtool \
        lua5.3 \
        make \
        man \
        perl \
        pkg-config \
        protobuf-compiler \
        protobuf-compiler-grpc \
        protobuf-c-compiler \
        python-ipaddress \
        python3 \
        python3-dev \
        python3-pytest \
        python3-sphinx \
        rsync \
        strace \
        systemd-coredump \
        sudo \
        tcpdump \
        texinfo \
        time \
        tmux \
        valgrind \
        vim \
        wget \
        x11-xserver-utils \
        xterm \
    && curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output /tmp/get-pip.py \
    && python2 /tmp/get-pip.py \
    && rm -f /tmp/get-pip.py \
    && pip install \
        exabgp==3.4.17 \
        "scapy>=2.4.2" \
        ipaddr \
        pytest

#RUN export DEBIAN_FRONTEND=noninteractive \
#    && apt-get install -y \
#    bridge-utils

# build and install libyang2
RUN git clone https://github.com/CESNET/libyang.git && \
    cd libyang && \
    git checkout v2.0.7 && \
    mkdir build; cd build && \
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr \
    -DCMAKE_BUILD_TYPE:String="Release" .. && \
    make -j $(nproc) && \
    sudo make install

# build and install newer json-c
RUN git clone https://github.com/json-c/json-c.git && \
    mkdir build-json-c && \
    cd build-json-c && \
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ../json-c && \
    make && make install

# build and install mininet 2.3.0-dev (w/o any open*)
RUN git clone https://github.com/choppsv1/mininet.git && \
        cd mininet && \
        PYTHON=python2 util/install.sh -n

# Requirements for FRR
RUN export DEBIAN_FRONTEND=noninteractive && \
        apt-get install -y libprotobuf-c-dev sqlite3 libsqlite3-dev libzmq3-dev libzmq5 librtr-dev librtr0

RUN groupadd -r -g 92 frr \
    && groupadd -r -g 85 frrvty \
    && useradd -c "FRRouting suite" \
               -d /var/run/frr \
               -g frr \
               -G frrvty \
               -r \
               -s /sbin/nologin \
               frr \
    && useradd -d /var/run/exabgp/ \
               -s /bin/false \
               exabgp

# Configure coredumps
RUN echo "" >> /etc/security/limits.conf; \
    echo "* soft core unlimited" >> /etc/security/limits.conf; \
    echo "root soft core unlimited" >> /etc/security/limits.conf; \
    echo "* hard core unlimited" >> /etc/security/limits.conf; \
    echo "root hard core unlimited" >> /etc/security/limits.conf

# Copy run scripts to facilitate users wanting to run the tests
COPY docker/inner /opt/topotests

ENV PATH "$PATH:/opt/topotests"

RUN echo "cat /opt/topotests/motd.txt" >> /root/.profile && \
      echo "export PS1='(topotests) $PS1'" >> /root/.profile

ENTRYPOINT [ "bash", "/opt/topotests/entrypoint.sh" ]
