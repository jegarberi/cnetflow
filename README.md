# CNetflow

A high-performance NetFlow collector and analyzer tool written in C, designed to capture, process, and store network
flow data for network monitoring and analysis.

Inspired from
https://github.com/tubav/libipfix

## Features

- **Multi-version NetFlow support**: NetFlow v5, v9, and IPFIX
- **High performance**: Asynchronous I/O using libuv
- **PostgreSQL integration**: Direct database storage for flow records
- **SNMP support**: Network device monitoring capabilities
- **Memory efficient**: Custom arena allocator and dynamic arrays
- **Systemd integration**: Native Linux service support
- **Docker support**: Containerized deployment option

## Architecture

CNetflow is built with a modular architecture consisting of several shared libraries:

- **collector**: Main flow collection engine
- **netflow**: Core NetFlow protocol handling
- **netflow_v5**: NetFlow version 5 implementation
- **netflow_v9**: NetFlow version 9 implementation
- **netflow_ipfix**: IPFIX (Internet Protocol Flow Information Export) support
- **db_psql**: PostgreSQL database interface
- **cnetflow_snmp**: SNMP monitoring capabilities
- **arena**: Memory arena allocator
- **hashmap**: Hash table implementation
- **dyn_array**: Dynamic array utilities

## Requirements

### Build Dependencies

- GCC compiler
- CMake 3.25 or higher
- PostgreSQL development libraries (`libpq-dev`)
- libuv development libraries (`libuv1-dev`)
- Net-SNMP development libraries (`libsnmp-dev`)

### Runtime Dependencies

- PostgreSQL server
- libuv
- Net-SNMP libraries

## Installation

### From Source

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd cnetflow
   ```

2. **Build the project:**
   ```bash
   mkdir build
   cd build
   cmake ..
   make
   ```

3. **Install:**
   ```bash
   sudo make install
   ```

### Using Package Manager

Build and install packages:

```bash
# Build packages
make package

# Install DEB package (Ubuntu/Debian)
sudo dpkg -i cnetflow-1.0.0-Linux.deb

# Install RPM package (Red Hat/CentOS/Fedora)
sudo rpm -i cnetflow-1.0.0-Linux.rpm