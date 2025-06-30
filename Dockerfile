FROM debian:bookworm-slim AS dependencies
LABEL authors="jon"

# Combine RUN commands to reduce layers and use --no-install-recommends to minimize image size
RUN apt update && apt install -y --no-install-recommends \
    postgresql-common
RUN yes | /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh
RUN apt install -y --no-install-recommends libuv1-dev \
    libpq-dev \
    libsnmp-dev \
    cmake \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

FROM dependencies AS compile
WORKDIR /tmp/cnetflow
# Use COPY instead of ADD when you don't need ADD's extra features
COPY . .
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release
RUN cmake --build build --config Release
RUN ctest -C Release --test-dir build

# Use minimal runtime image to reduce final image size
FROM debian:bookworm-slim AS runtime

# Install only runtime dependencies
RUN apt update && apt install -y --no-install-recommends \
    postgresql-common
RUN yes | /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh
RUN apt update && apt install -y --no-install-recommends \
    libuv1 \
    libpq5 \
    libsnmp40 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r cnetflow && useradd -r -g cnetflow cnetflow

# Create application directory
RUN mkdir -p /app && chown cnetflow:cnetflow /app
WORKDIR /app

# Copy only necessary files from compile stage
COPY --from=compile --chown=cnetflow:cnetflow /tmp/cnetflow/build/*.so ./
COPY --from=compile --chown=cnetflow:cnetflow /tmp/cnetflow/build/cnetflow ./

# Switch to non-root user
USER cnetflow

# Use EXEC form for better signal handling
CMD ["./cnetflow"]

