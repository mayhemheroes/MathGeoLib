FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang cmake

COPY . /repo
WORKDIR /repo/build
RUN cmake ..
RUN make -j8

RUN clang++ /repo/mayhem/fuzz_FromString.cpp -fsanitize=fuzzer,address -I /repo/src/ /repo/build/libMathGeoLib.a  -o /fuzz

FROM ubuntu:22.04 as package

COPY --from=builder /fuzz /fuzz_FromString
