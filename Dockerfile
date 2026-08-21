FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    python3 \
    python3-pip \
    pkg-config \
    flex \
    bison \
    m4 \
    && rm -rf /var/lib/apt/lists/*

# Install Conan
RUN pip3 install conan==2.5.0 --break-system-packages

WORKDIR /app
RUN conan profile detect --force

# CACHE LAYER: Copy ONLY conanfile.txt and install dependencies
COPY conanfile.txt .
RUN conan install . --build=missing -s build_type=Release -c "tools.build:cflags=['-std=gnu11']" -o "*:shared=False"

# BUILD LAYER: Copy the rest of the source
COPY . .
# Now build the project using the Conan toolchain
RUN cmake -B build/Release -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=build/Release/generators/conan_toolchain.cmake -DBUILD_STATIC=ON
RUN cmake --build build/Release --config Release -j$(nproc)

# RUNTIME LAYER
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Install minimum runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r cnetflow && useradd -r -g cnetflow cnetflow
RUN mkdir -p /app && chown cnetflow:cnetflow /app
WORKDIR /app

# Copy statically linked binary
COPY --from=builder /app/build/Release/cnetflow ./cnetflow
RUN chmod +x ./cnetflow

USER cnetflow
CMD ["./cnetflow"]

