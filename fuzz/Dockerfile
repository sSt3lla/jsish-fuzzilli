FROM swift

ENV DEBIAN_FRONTEND=noninteractive
ENV SHELL=bash

RUN apt-get update && \
    apt-get install -y git build-essential bison wget clang libreadline-dev

RUN git clone https://github.com/googleprojectzero/fuzzilli.git fuzzilli

WORKDIR /fuzzilli/Targets

RUN git clone https://github.com/sSt3lla/jsish-fuzzilli jsish-fuzzilli
WORKDIR jsish-fuzzilli
RUN make && make -C fuzz


#Add the profile
RUN cp fuzz/jsishProfile.swift /fuzzilli/Sources/FuzzilliCli/Profiles

#Edit the main.swift
RUN sed -i '/let profiles = \[/a\    "jsish": jsishProfile,' /fuzzilli/Sources/FuzzilliCli/Profiles/Profile.swift

WORKDIR /fuzzilli
RUN swift build -c release

#CMD ["swift run -c release FuzzilliCli --profile=jsish --storagePath=FuzzStorage/ --jobs=$NUM_CORES --resume Targets/jsish/fuzz/fuzz"]