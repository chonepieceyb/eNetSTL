# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build System

This project uses CMake with a custom build script. The primary build commands are:

### Standard Build
```bash
./build.sh                    # Build with default settings (LOG_LEVEL=0)
./build.sh -DLOG_LEVEL=4      # Build with verbose logging
./build.sh -DUSE_STATIC=ON    # Build with static libraries
./build.sh -d                 # Build using Docker container
```

### Manual CMake Build
```bash
mkdir -p build && cd build
cmake -DLOG_LEVEL=0 -DUSE_LATENCY_EXP=off ..
make -j$(nproc)
```

### Clean Commands
```bash
make cmake_clean              # Remove build artifacts only
make clean_all                # Complete clean (removes bin, build, install, bpf_skel)
sudo rm -rf build             # Remove entire build directory
```

### Key CMake Options
- `LOG_LEVEL` (0-4): Controls verbosity of output
- `USE_LATENCY_EXP` (ON/OFF): Enable latency evaluation features
- `USE_STATIC` (ON/OFF): Compile with static libraries
- `LINUX_PATH`: Path to custom Linux kernel source (defaults to system libbpf)

## Project Architecture

eNetSTL is a high-performance networking framework with three main components:

### 1. eBPF Programs (`src/bpf_kern/`)
- **Kernel-space network functions** using XDP for high-speed packet processing
- Organized by experiment (`exp1-2`, `exp3`, `exp4`, etc.)
- Each experiment has its own subdirectory with specific eBPF implementations
- Uses BPF skeleton mechanism for user-space communication
- Located in: `install/bpf_kern_objs/` after build

### 2. User-space Programs (`src/c/`)
- **Control plane applications** that load and manage eBPF programs
- Correspond to eBPF experiments (matching directory structure)
- Generate BPF skeleton headers in `src/c/bpf_skel/` during build
- Executables output to: `bin/` directory
- Test helpers in `test_helpers.h`

### 3. Kernel Modules (`src/LKMs/`)
- **Loadable kernel modules** for extended functionality
- Includes eNetSTL SIMD parallel hash library
- Pointer class basic library
- Experimental modules for specific functionality

### 4. Python Scripts (`src/python/`)
- **Experiment automation** and data collection
- Configuration management in `exp_config.py`
- Performance testing and analysis scripts

## Key Development Patterns

### eBPF + User-space Communication
- Uses **BPF skeleton** pattern for type-safe communication
- Skeleton headers auto-generated during build in `src/c/bpf_skel/`
- Maps and data structures shared between kernel and user space

### Build Dependencies
- **clang-15** compiler (required for eBPF compilation)
- **libbpf** for eBPF program loading
- Custom Linux kernel source optional (enhances debugging)

### Testing Infrastructure
- Remote debugging via SSH (scripts in `scripts/` directory)
- eBPF program tracing through `/sys/kernel/debug/tracing/trace_pipe`
- Test executables built alongside main applications

## Configuration Files

### Network Interface
Configure the receiving interface in `src/c/config.h`:
```c
#define XDP_IF "<Interface Name>"
```

### Experiment Configuration
Python scripts configured via `src/python/exp_config.py`:
- `interface_name`: Packet receiving NIC
- `TREX_SERVER`: Packet sender IP address
- `LAT_TEST_PORT`: Trex configuration port

## Testing and Debugging

### Remote Testing Setup
```bash
# Start remote debugging server
scripts/new_kernel_dbg_session.sh

# Connect to remote server
sshpass -p "123456" ssh -o StrictHostKeyChecking=no -p 3333 seu@127.0.0.1

# Monitor eBPF program output
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Test Execution
1. Build test executables (appear in `bin/`)
2. Copy to remote server for execution
3. Run with sudo privileges
4. Monitor eBPF logs via trace_pipe
5. Check test results and fix issues accordingly

### Common Issues
- **trace_pipe busy**: Kill process holding the file descriptor
- **eBPF loading failures**: Check libbpf API compatibility
- **SSH connection issues**: Clear `~/.ssh/known_hosts` and restart server

## Docker Support

The project supports Docker builds for consistent environments:
- Pre-built image: `chonepieceyb/enetstl:v0.1`
- Custom builds via `Docker/` directory
- Linux kernel source mounted automatically if available

## Experimental Features

### Latency Experiments
Enable with `-DUSE_LATENCY_EXP=on` CMake flag for latency evaluation capabilities.

### Selective Compilation
Blacklist files via `cmake/bpf_blacklist.txt` and `cmake/c_blacklist.txt` to exclude specific components from build.