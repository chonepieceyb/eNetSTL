# eNetSTL Skeleton Generation System

This directory contains the skeleton generation system for eNetSTL, which automates the creation of eBPF programs, user-space applications, and kernel modules following the project's established patterns.

## Files Overview

### Core Components

- **`skels_common.py`** - Abstract base class for all skeleton generators with shared functionality
- **`gen_skels.py`** - Main interactive skeleton generator that orchestrates other generators

### Individual Skeleton Generators

- **`gen_bpf_common_header.py`** - Generates common BPF header sections
- **`gen_xdp_skel.py`** - Generates XDP program skeleton with user-space loader
- **`gen_kfunc_skel.py`** - Generates kfunc BPF programs and corresponding LKM
- **`gen_xdp_testing_skel.py`** - Generates XDP testing framework

### Specifications

- **`specifications/`** - Directory containing specification files that define the requirements for each generator

## Usage

### Basic Usage

Generate a complete skeleton for a new subproject interactively:

```bash
cd skeletons
python3 gen_skels.py
```

The generator will guide you through an interactive session to collect all required information.

### Interactive Prompts

The generator will ask for the following information:

1. **Subproject name** (required): Name of your subproject (letters, numbers, underscores, hyphens only)
2. **Program type**: Currently only XDP is supported
3. **Features**: Optional features like `kfunc` for kernel function support
4. **Author name** (required): Your name
5. **Version number** (required): Version in format like 1.0.0
6. **Project root** (optional): Path to project root (defaults to parent directory)

After collecting all information, the generator will show a summary and ask for confirmation before proceeding.

### Generated Files

The generator will create the following files based on the configuration:

#### BPF Kernel File
- Path: `PROJECT_ROOT/src/bpf_kern/{subproject}/{subproject}.bpf.c`
- Contains the eBPF program implementation

#### BPF User Files
- Path: `PROJECT_ROOT/src/c/{subproject}/{subproject}_user.c`
- Path: `PROJECT_ROOT/src/c/{subproject}/test_{subproject}_user.c`
- Contains the user-space loader and control logic (main and test versions)

#### LKM Files (if kfunc feature enabled)
- Path: `PROJECT_ROOT/src/LKMs/{subproject}/module.c`
- Path: `PROJECT_ROOT/src/LKMs/{subproject}/Makefile`
- Contains kernel module for kfunc implementation

## Examples

### Interactive Session Example

```
$ python3 gen_skels.py
=== eNetSTL Skeleton Generator ===
This interactive generator will create a complete skeleton for your eNetSTL subproject.

Enter subproject name (required): packet_filter

Available program types:
1. XDP - XDP program for high-speed packet processing
Select program type [1]:

Available features:
1. kfunc - Kernel function support (requires LKM)
2. None - Basic XDP program only
Select features (enter numbers separated by spaces, or press Enter for None):

Enter author name (required): John Doe
Enter version number (e.g., 1.0.0) (required): 1.0.0
Enter project root path [/mnt/disk1/yangbin/CODING/WorkSpace/eNetSTL]:

==================================================
GENERATION SUMMARY:
Subproject: packet_filter
Program type: XDP
Features: None
Author: John Doe
Version: 1.0.0
Project root: /mnt/disk1/yangbin/CODING/WorkSpace/eNetSTL
==================================================
Proceed with generation? [y/N]: y

Generating skeleton for subproject: packet_filter
✓ Generated: /mnt/disk1/yangbin/CODING/WorkSpace/eNetSTL/src/bpf_kern/packet_filter/packet_filter.bpf.c
✓ Generated: /mnt/disk1/yangbin/CODING/WorkSpace/eNetSTL/src/c/packet_filter/packet_filter_user.c
✓ Generated: /mnt/disk1/yangbin/CODING/WorkSpace/eNetSTL/src/c/packet_filter/test_packet_filter_user.c
✓ Generated: /mnt/disk1/yangbin/CODING/WorkSpace/eNetSTL/src/LKMs/packet_filter/module.c
✓ Generated: /mnt/disk1/yangbin/CODING/WorkSpace/eNetSTL/src/LKMs/packet_filter/Makefile

🎉 Skeleton generation completed successfully!

Next steps:
1. Navigate to your subproject directory
2. Implement your custom logic in the generated files
3. Build the project using: ./build.sh
4. Test your implementation
```

## Architecture

The skeleton generation system follows a modular design:

1. **CommonSkeleton** - Base class providing shared functionality
2. **Specific Generators** - Inherit from CommonSkeleton to implement specific code generation
3. **Main Generator** - Orchestrates multiple generators and merges their outputs
4. **Specifications** - Define the requirements and patterns for each generator type

### Shared vs Exclusive Code Sections

- **Shared sections**: Multiple generators contribute code that gets merged (e.g., common headers)
- **Exclusive sections**: Only one generator provides code (e.g., main function, module init/exit)

## Integration with Build System

Generated files are compatible with the eNetSTL build system:

- BPF programs are automatically compiled during the build process
- Skeleton headers are generated in `src/c/bpf_skel/`
- User programs are compiled to the `bin/` directory
- Kernel modules can be built using their respective Makefiles

## Extending the System

To add new skeleton types:

1. Create a new generator class inheriting from `CommonSkeleton`
2. Implement the required methods following the specification patterns
3. Add the new generator to the main `gen_skels.py` orchestrator
4. Update specification files as needed

## Testing

Individual generators can be tested by running them directly:

```bash
python3 gen_xdp_skel.py
python3 gen_kfunc_skel.py
python3 gen_xdp_testing_skel.py
```

Each script will output example code snippets when run without parameters.