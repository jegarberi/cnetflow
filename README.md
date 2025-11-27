# Monitor de Análisis de Redes y Control Estadístico (MARCE)

A high-performance NetFlow collector and analyzer tool written in C, designed to capture, process, and store network
flow data for network monitoring and analysis.

Inspired from
https://github.com/tubav/libipfix

## Features

- **Multi-version NetFlow support**: NetFlow v5, v9, and IPFIX
- **High performance**: Asynchronous I/O using libuv
- **PostgreSQL integration**: Direct database storage for flow records
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
- **arena**: Memory arena allocator
- **hashmap**: Hash table implementation
- **dyn_array**: Dynamic array utilities

## Requirements

### Build Dependencies

- GCC compiler
- CMake 3.25 or higher
- PostgreSQL development libraries (`libpq-dev`)
- libuv development libraries (`libuv1-dev`)

### Runtime Dependencies

- PostgreSQL server
- libuv

## Installation

### From Source

1. **Clone the repository:**
   ```bash
   git clone https://github.com/jegarberi/cnetflow
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
```



### Lists

- [Abuse.ch URLhaus](https://urlhaus.abuse.ch/downloads/hostfile/)
- [Emerging Threats](https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
- [IPsum Threat Intelligence Feed](https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt)
- [NoCoin Filter List](https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt)
- [Stratosphere Lab](https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_historical_blacklist_prioritized_by_newest_attackers.csv)
- [ThreatFox](https://threatfox.abuse.ch/downloads/hostfile/)
- [dshield 7 days](https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield_7d.netset)


https://github.com/firehol/blocklist-ipsets/

