#!/usr/bin/env python3
"""
Test script for the skeleton generator that provides sample input.
"""

import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from gen_skels import SkeletonGenerator


def test_generator():
    """Test the skeleton generator with sample parameters."""
    print("=== Testing eNetSTL Skeleton Generator ===")

    # Sample parameters for testing
    test_params = {
        'subproject': 'test_project',
        'prog_type': 'XDP',
        'feature_lists': ['kfunc'],
        'author_name': 'Test Author',
        'version': '1.0.0',
        'project_root': str(Path(__file__).parent.parent)
    }

    print(f"Testing with parameters:")
    for key, value in test_params.items():
        print(f"  {key}: {value}")
    print()

    generator = SkeletonGenerator(test_params['project_root'])

    try:
        # Test generation
        generator.generate_skeleton(
            test_params['subproject'],
            test_params['prog_type'],
            test_params['feature_lists'],
            test_params['author_name'],
            test_params['version']
        )

        print(f"\n🎉 Test generation completed successfully!")

        # Verify files were created
        project_root = Path(test_params['project_root'])
        files_to_check = [
            f"src/bpf_kern/{test_params['subproject']}/{test_params['subproject']}.bpf.c",
            f"src/c/{test_params['subproject']}/{test_params['subproject']}_user.c",
            f"src/c/{test_params['subproject']}/test_{test_params['subproject']}_user.c",
            f"src/LKMs/{test_params['subproject']}/module.c",
            f"src/LKMs/{test_params['subproject']}/Makefile"
        ]

        print(f"\nVerifying generated files:")
        for file_path in files_to_check:
            full_path = project_root / file_path
            if full_path.exists():
                print(f"  ✓ {file_path}")
            else:
                print(f"  ✗ {file_path} (not found)")

        return True

    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False


if __name__ == "__main__":
    success = test_generator()
    sys.exit(0 if success else 1)