#!/usr/bin/env python3
"""
Interactive generation of skeleton by using other skeleton generation scripts.
Implements the gen_skels.spec.md specification with interactive user input.
"""

import os
import sys
from pathlib import Path
from typing import List, Dict, Any

from gen_bpf_common_header import BpfCommonHeaderSkeleton
from gen_xdp_skel import XdpSkeleton
from gen_kfunc_skel import KfuncSkeleton
from gen_xdp_testing_skel import XdpTestingSkeleton


class SkeletonGenerator:
    """Main skeleton generator that orchestrates different skeleton types."""

    def __init__(self, project_root: str = None):
        if project_root is None:
            self.project_root = Path(__file__).parent.parent
        else:
            self.project_root = Path(project_root)

        self.skeletons = {
            'bpf_common_header': BpfCommonHeaderSkeleton(),
            'xdp': XdpSkeleton(),
            'xdp_testing': XdpTestingSkeleton(),
            'kfunc': KfuncSkeleton()
        }

    def get_user_input(self) -> Dict[str, Any]:
        """Get user input interactively."""
        print("=== eNetSTL Skeleton Generator ===")
        print("This interactive generator will create a complete skeleton for your eNetSTL subproject.\n")

        # Get subproject name
        while True:
            subproject = input("Enter subproject name (required): ").strip()
            if subproject:
                if not subproject.replace('_', '').replace('-', '').isalnum():
                    print("Error: Subproject name should contain only letters, numbers, underscores, and hyphens.")
                    continue
                break
            print("Error: Subproject name is required.")

        # Get program type
        print("\nAvailable program types:")
        print("1. XDP - XDP program for high-speed packet processing")

        while True:
            choice = input("Select program type [1]: ").strip()
            if not choice or choice == "1":
                prog_type = "XDP"
                break
            else:
                print("Invalid choice. Please enter 1 or press Enter for XDP.")

        # Get features
        print("\nAvailable features:")
        print("1. kfunc - Kernel function support (requires LKM)")
        print("2. None - Basic XDP program only")

        feature_lists = []
        while True:
            feature_choice = input("Select features (enter numbers separated by spaces, or press Enter for None): ").strip()
            if not feature_choice:
                break

            selected_features = feature_choice.split()
            valid = True
            for feat in selected_features:
                if feat not in ["1", "2"]:
                    print(f"Invalid choice: {feat}")
                    valid = False
                    break

            if valid:
                if "1" in selected_features:
                    feature_lists.append("kfunc")
                break

        # Get author name
        while True:
            author_name = input("Enter author name (required): ").strip()
            if author_name:
                break
            print("Error: Author name is required.")

        # Get version
        while True:
            version = input("Enter version number (e.g., 1.0.0) (required): ").strip()
            if version:
                # Simple version validation
                parts = version.split('.')
                if len(parts) >= 2 and all(part.isdigit() for part in parts):
                    break
                else:
                    print("Error: Version should be in format like 1.0.0 (numeric parts separated by dots).")
            else:
                print("Error: Version is required.")

        # Get project root (optional)
        default_root = str(self.project_root)
        project_root_input = input(f"Enter project root path [{default_root}]: ").strip()
        project_root = project_root_input if project_root_input else default_root

        # Confirm and show summary
        print("\n" + "="*50)
        print("GENERATION SUMMARY:")
        print(f"Subproject: {subproject}")
        print(f"Program type: {prog_type}")
        print(f"Features: {', '.join(feature_lists) if feature_lists else 'None'}")
        print(f"Author: {author_name}")
        print(f"Version: {version}")
        print(f"Project root: {project_root}")
        print("="*50)

        while True:
            confirm = input("Proceed with generation? [y/N]: ").strip().lower()
            if confirm in ['y', 'yes']:
                break
            elif confirm in ['n', 'no', '']:
                print("Generation cancelled.")
                sys.exit(0)
            else:
                print("Please enter 'y' for yes or 'n' for no.")

        return {
            'subproject': subproject,
            'prog_type': prog_type,
            'feature_lists': feature_lists,
            'author_name': author_name,
            'version': version,
            'project_root': project_root
        }

    def merge_code_snippets(self, snippets: List[str]) -> str:
        """Merge multiple code snippets into one file."""
        return '\n\n'.join(filter(None, snippets))

    def generate_bpf_kern_file(self, subproject: str, prog_type: str,
                              feature_lists: List[str], author_name: str, version: str) -> str:
        """Generate BPF kernel file content."""
        headers_list = []
        impls_list = []
        final_snippets = []

        # Always include common header
        headers_list.append('bpf_common_header')

        # Add program type specific skeleton
        if prog_type == 'XDP':
            xdp_skel = XdpSkeleton(subproject, author_name, version)
        else:
            raise ValueError(f"Unsupported program type: {prog_type}")

        # Add feature-specific skeletons
        if 'kfunc' in feature_lists:
            headers_list.append('kfunc')
            kfunc_skel = KfuncSkeleton(subproject, author_name=author_name, version=version)

        # Step 1: Collect all headers
        for script in headers_list:
            if script == 'bpf_common_header':
                skeleton = self.skeletons['bpf_common_header']
                final_snippets.append(skeleton.skel_bpf_header_sec())
            elif script == 'kfunc':
                final_snippets.append(kfunc_skel.skel_bpf_header_sec())

        # Step 2: Collect all impls (none for BPF kernel currently)

        # Step 3: Add program-specific code
        final_snippets.append(xdp_skel.skel_bpf_prog_sec())

        return self.merge_code_snippets(final_snippets)

    def generate_bpf_user_file(self, subproject: str, prog_type: str,
                              feature_lists: List[str], author_name: str, version: str) -> Dict[str, str]:
        """Generate BPF user files content."""
        scripts_list = []
        test_scripts_list = []

        if prog_type == 'XDP':
            scripts_list.append('xdp')
            test_scripts_list.append('xdp_testing')
            xdp_skel = XdpSkeleton(subproject, author_name, version)
            xdp_test_skel = XdpTestingSkeleton(subproject, author_name, version)
        else:
            raise ValueError(f"Unsupported program type: {prog_type}")

        # Generate main user file following proper merging logic
        main_headers = []
        main_impls = []
        main_final = []

        # Step 1: Collect headers
        main_headers.append(xdp_skel.skel_user_c_header_sec(subproject=subproject))

        # Step 2: Collect impls
        main_impls.append(xdp_skel.skel_user_c_impl_sec())

        # Step 3: Add main function
        main_final.append(xdp_skel.skel_user_c_main_sec(subproject=subproject))

        # Merge: [headers] [impl] [main]
        main_snippets = main_headers + main_impls + main_final

        # Generate test user file following proper merging logic
        test_headers = []
        test_impls = []
        test_final = []

        # Step 1: Collect headers
        test_headers.append(xdp_test_skel.skel_user_c_header_sec(subproject=subproject))

        # Step 2: Collect impls
        test_impls.append(xdp_test_skel.skel_user_c_impl_sec(subproject=subproject))

        # Step 3: Add main function
        test_final.append(xdp_test_skel.skel_user_c_main_sec())

        # Merge: [headers] [impl] [main]
        test_snippets = test_headers + test_impls + test_final

        return {
            f"{subproject}_user.c": self.merge_code_snippets(main_snippets),
            f"test_{subproject}_user.c": self.merge_code_snippets(test_snippets)
        }

    def generate_lkm_files(self, subproject: str, feature_lists: List[str],
                          author_name: str, version: str) -> Dict[str, str]:
        """Generate LKM files if applicable."""
        if 'kfunc' not in feature_lists:
            return {}

        kfunc_skel = KfuncSkeleton(subproject, author_name=author_name, version=version)

        # Generate module.c following proper merging logic
        lkm_headers = []
        lkm_impls = []
        lkm_final = []

        # Step 1: Collect headers
        lkm_headers.append(kfunc_skel.skel_lkm_header_sec())

        # Step 2: Collect impls
        lkm_impls.append(kfunc_skel.skel_lkm_impl_sec(subproject=subproject))

        # Step 3: Add init_exit functions
        lkm_final.append(kfunc_skel.skel_lkm_init_exit(subproject=subproject,
                                                      author_name=author_name, version=version))

        # Merge: [headers] [impl] [init_exit]
        module_content = self.merge_code_snippets(lkm_headers + lkm_impls + lkm_final)

        makefile_content = kfunc_skel.skel_lkm_makefile(subproject=subproject)

        return {
            'module.c': module_content,
            'Makefile': makefile_content
        }

    def generate_skeleton(self, subproject: str, prog_type: str, feature_lists: List[str],
                         author_name: str, version: str) -> None:
        """Generate complete skeleton for a subproject."""
        print(f"\nGenerating skeleton for subproject: {subproject}")
        print(f"Program type: {prog_type}")
        print(f"Features: {feature_lists}")
        print(f"Author: {author_name}")
        print(f"Version: {version}")
        print()

        # Generate BPF kernel file
        bpf_kern_content = self.generate_bpf_kern_file(
            subproject, prog_type, feature_lists, author_name, version)
        bpf_kern_path = self.project_root / "src" / "bpf_kern" / subproject / f"{subproject}.bpf.c"

        # Create directory if it doesn't exist
        bpf_kern_path.parent.mkdir(parents=True, exist_ok=True)

        # Write BPF kernel file
        with open(bpf_kern_path, 'w') as f:
            f.write(f"/*\n * Author: {author_name}\n * Version: {version}\n */\n\n")
            f.write(bpf_kern_content)
        print(f"✓ Generated: {bpf_kern_path}")

        # Generate BPF user files
        user_files = self.generate_bpf_user_file(
            subproject, prog_type, feature_lists, author_name, version)
        user_dir = self.project_root / "src" / "c" / subproject
        user_dir.mkdir(parents=True, exist_ok=True)

        for filename, content in user_files.items():
            file_path = user_dir / filename
            with open(file_path, 'w') as f:
                f.write(f"/*\n * Author: {author_name}\n * Version: {version}\n */\n\n")
                f.write(content)
            print(f"✓ Generated: {file_path}")

        # Generate LKM files if applicable
        lkm_files = self.generate_lkm_files(subproject, feature_lists, author_name, version)
        if lkm_files:
            # module.c goes to src/LKMs/subproject/
            lkm_dir = self.project_root / "src" / "LKMs" / subproject
            lkm_dir.mkdir(parents=True, exist_ok=True)

            # Makefile goes to src/bpf_kern/subproject/
            makefile_dir = self.project_root / "src" / "LKMs" / subproject
            makefile_dir.mkdir(parents=True, exist_ok=True)

            for filename, content in lkm_files.items():
                if filename == 'module.c':
                    file_path = lkm_dir / filename
                    file_type = 'c'
                else:  # Makefile
                    file_path = makefile_dir / filename
                    file_type = 'makefile'

                with open(file_path, 'w') as f:
                    if file_type == 'makefile':
                        f.write(f"# Author: {author_name}\n# Version: {version}\n\n")
                    else:
                        f.write(f"/*\n * Author: {author_name}\n * Version: {version}\n */\n\n")
                    f.write(content)
                print(f"✓ Generated: {file_path}")


def main():
    generator = SkeletonGenerator()

    try:
        # Get user input interactively
        params = generator.get_user_input()

        # Update project root if user provided different path
        generator.project_root = Path(params['project_root'])

        # Generate skeleton
        generator.generate_skeleton(
            params['subproject'],
            params['prog_type'],
            params['feature_lists'],
            params['author_name'],
            params['version']
        )

        print(f"\n🎉 Skeleton generation completed successfully!")
        print(f"\nNext steps:")
        print(f"1. Navigate to your subproject directory")
        print(f"2. Implement your custom logic in the generated files")
        print(f"3. Build the project using: ./build.sh")
        print(f"4. Test your implementation")

    except KeyboardInterrupt:
        print(f"\n\nGeneration cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error generating skeleton: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()