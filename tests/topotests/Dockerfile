FROM ubuntu:20.04
ARG DEBIAN_FRONTEND=noninteractive

RUN export DEBIAN_FRONTEND=noninteractive \
    && apt-get update \
    && apt-get install -y \
        autoconf \
        automake \
        binutils \
        bison \
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
        libpam0g-dev \
        libpcre2-dev \
        libpython3-dev \
        libreadline-dev \
        libsnmp-dev \
        libsystemd-dev \
        libtool \
        make \
        man \
        mininet \
        perl \
        pkg-config \
        protobuf-compiler-grpc \
        python-ipaddress \
        python3 \
        python3-dev \
        python3-pytest \
        python3-sphinx \
        rsync \
        strace \
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
        pytest \
    && rm -rf /var/lib/apt/lists/*

# build and install libyang2
RUN git clone https://github.com/CESNET/libyang.git && \
    cd libyang && \
    git checkout v2.0.7 && \
    mkdir build; cd build && \
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr \
    -DCMAKE_BUILD_TYPE:String="Release" .. && \
    make -j $(nproc) && \
    sudo make install

RUN rm -rf /var/lib/apt/lists/*

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
