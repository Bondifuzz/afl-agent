########################################
# Base image
########################################

FROM python:3.7-slim AS base
SHELL ["/bin/bash", "-c"]
ENV PYTHONUNBUFFERED=1
WORKDIR /fuzzer
USER root

RUN apt-get update
RUN apt-get install -y --no-install-recommends git

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements*.txt ./
RUN pip3 install -r requirements-prod.txt

########################################
# Release image
########################################

FROM python:3.7-slim
SHELL ["/bin/bash", "-c"]
ENV PYTHONUNBUFFERED=1
WORKDIR /fuzzer

ARG ENVIRONMENT=dev
ARG SERVICE_NAME=afl-agent
ARG SERVICE_VERSION=None
ARG COMMIT_ID=None
ARG COMMIT_DATE=None
ARG BUILD_DATE=None
ARG GIT_BRANCH=None

ENV ENVIRONMENT=$ENVIRONMENT
ENV SERVICE_NAME=$SERVICE_NAME
ENV SERVICE_VERSION=$SERVICE_VERSION
ENV COMMIT_ID=$COMMIT_ID
ENV COMMIT_DATE=$COMMIT_DATE
ENV BUILD_DATE=$BUILD_DATE
ENV GIT_BRANCH=$GIT_BRANCH

RUN apt-get update

RUN DEBIAN_FRONTEND="noninteractive" apt -y install \
        build-essential \
        clang \
        git \
        llvm && \

    DEBIAN_FRONTEND="noninteractive" apt -y install \
        gcc-$(gcc -dumpversion | egrep -o "^[0-9]+")-plugin-dev && \

    # optimin packages
    DEBIAN_FRONTEND="noninteractive" apt -y install \
        cmake \
        zlib1g \
        zlib1g-dev && \

    # install afl
    git clone --depth 1 --branch v4.08c https://github.com/AFLplusplus/AFLplusplus && \
    cd ./AFLplusplus && \
    make install && \

	cd ../../../../ && \
    rm -rf /AFLplusplus && \

    # cleanup
    apt -y purge \
        build-essential \
        git \
        gcc-$(gcc -dumpversion | egrep -o "^[0-9]+")-plugin-dev \
        cmake \
        zlib1g-dev && \

    apt -y autoremove && \

    rm /var/log/dpkg.log && \
    #rm /var/log/bootstrap.log && \
    rm /var/log/alternatives.log && \
    rm -rf /var/lib/ && \
    rm -rf /var/cache/apt/ && \
    rm -rf /var/cache/debconf/

COPY agent ./agent
COPY logging.yaml .
COPY --from=base /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"
CMD python3 -m agent
