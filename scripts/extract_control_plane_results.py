#!/usr/bin/env python3
import os
import re
import csv
import glob
from pathlib import Path

def extract_parameters_from_filename(filename):
    """
    Extract control_plane_type, entries_num, update_interval_ms from filename
    Format: {number}-cp_cuckoo_hash_{control_plane_type}_{entries_num}_{update_interval_ms}.csv
    Control plane types can be: no_shared, shared, in_kernel
    """
    # Remove prefix number and extension
    basename = os.path.basename(filename)
    # Remove the number prefix and .csv extension
    name_without_prefix = basename.split('-', 1)[1] if '-' in basename else basename
    name_without_ext = name_without_prefix.replace('.csv', '')

    # Split the parts
    parts = name_without_ext.split('_')
    if len(parts) >= 6 and parts[0] == 'cp' and parts[1] == 'cuckoo' and parts[2] == 'hash':
        # Control plane type can be one word or multiple (like "no_shared")
        # We know the pattern is: cp_cuckoo_hash_{type}_{entries}_{interval}
        # The last two parts are always entries and interval

        # Extract update interval (last part)
        update_interval_ms = parts[-1]
        if update_interval_ms.endswith('ms'):
            update_interval_ms = int(update_interval_ms[:-2])
        else:
            update_interval_ms = int(update_interval_ms)

        # Extract entries number (second to last part)
        entries_num = int(parts[-2])

        # Control plane type is everything between "hash" and entries
        control_plane_type = '_'.join(parts[3:-2])

        return control_plane_type, entries_num, update_interval_ms

    return None, None, None

def calculate_pps_stats(csv_file):
    """
    Calculate avg, min, max PPS values from a CSV file
    CSV format: pps_value,0.0 (one value per line)
    """
    pps_values = []

    try:
        with open(csv_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Split by comma and take the first value (pps)
                    parts = line.split(',')
                    if parts and parts[0]:
                        try:
                            pps = float(parts[0])
                            pps_values.append(pps)
                        except ValueError:
                            continue
    except Exception as e:
        print(f"Error reading {csv_file}: {e}")
        return None, None, None

    if not pps_values:
        return None, None, None

    pps_avg = sum(pps_values) / len(pps_values)
    pps_min = min(pps_values)
    pps_max = max(pps_values)

    return pps_avg, pps_min, pps_max

def main():
    # Project root directory
    project_root = Path(__file__).parent.parent
    logs_dir = project_root / "log" / "pps"

    # Find all CSV files with cp_cuckoo_hash pattern
    pattern = str(logs_dir / "*cp_cuckoo_hash_*")
    csv_files = glob.glob(pattern)

    if not csv_files:
        print(f"No CSV files found matching pattern: {pattern}")
        return

    # Results list
    results = []

    # Process each CSV file
    for csv_file in sorted(csv_files):
        print(f"Processing: {csv_file}")

        # Extract parameters from filename
        control_plane_type, entries_num, update_interval_ms = extract_parameters_from_filename(csv_file)

        if control_plane_type is None:
            print(f"Warning: Could not extract parameters from {csv_file}")
            continue

        # Calculate PPS statistics
        pps_avg, pps_min, pps_max = calculate_pps_stats(csv_file)

        if pps_avg is None:
            print(f"Warning: Could not calculate PPS stats for {csv_file}")
            continue

        # Add to results
        results.append({
            'control_plane_type': control_plane_type,
            'entries_num': entries_num,
            'update_interval_ms': update_interval_ms,
            'pps_avg': pps_avg,
            'pps_min': pps_min,
            'pps_max': pps_max
        })

    # Sort results by control_plane_type, entries_num, update_interval_ms
    results.sort(key=lambda x: (x['control_plane_type'], x['entries_num'], x['update_interval_ms']))

    # Write output CSV
    output_file = project_root / "control_plane_results.csv"

    with open(output_file, 'w', newline='') as f:
        fieldnames = ['control_plane_type', 'entries_num', 'update_interval_ms', 'pps_avg', 'pps_min', 'pps_max']
        writer = csv.DictWriter(f, fieldnames=fieldnames)

        writer.writeheader()
        for result in results:
            writer.writerow(result)

    print(f"\nResults written to: {output_file}")
    print(f"Processed {len(results)} files")

if __name__ == "__main__":
    main()