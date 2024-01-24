import argparse
import numpy as np
from scipy import stats

from utils import *

DEFAULT_MAX_GEOSAMPLING_SIZE = 1024


def gen_geo_cnts(prob, max_geosampling_size):
    geo_cnts = []
    geo_var = stats.geom(prob)
    for _ in range(max_geosampling_size):
        geo_cnts.append(str(geo_var.rvs()))
    return geo_cnts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-o",
        "--output",
        action="append",
        required=True,
        help="paths to generated header files",
    )
    parser.add_argument(
        "-p",
        "--probability-percent",
        type=int,
        action="append",
        required=True,
        help="update probability in percent",
    )
    parser.add_argument(
        "--cpus",
        type=int,
        default=total_cpu,
        help=f"ONLINE_CPU_NUM; defaults to current online CPU count {total_cpu}",
    )
    parser.add_argument(
        "--max-geosampling-size",
        type=int,
        default=DEFAULT_MAX_GEOSAMPLING_SIZE,
        help=f"MAX_GEOSAMPLING_SIZE; defaults to {DEFAULT_MAX_GEOSAMPLING_SIZE}",
    )
    args = parser.parse_args()

    content = ""
    content += f"""#ifndef _GEO_SAMPLING_POOL_H
#define _GEO_SAMPLING_POOL_H

#define ONLINE_CPU_NUM {args.cpus}
#define MAX_GEOSAMPLING_SIZE {args.max_geosampling_size}
"""
    for i, prob_percent in enumerate(args.probability_percent):
        prob = prob_percent / 100
        content += f"""
#{'el' if i else ''}if SK_NITRO_UPDATE_PROB_PERCENT == {prob_percent}
uint32_t GEO_SAMPLING_POOL[ONLINE_CPU_NUM][MAX_GEOSAMPLING_SIZE] = {{
"""
        for _ in range(args.cpus):
            content += (
                "\t{"
                + ", ".join(map(str, gen_geo_cnts(prob, args.max_geosampling_size)))
                + "},\n"
            )
        content += "};"
    content += """
#else
#error unsupported SK_NITRO_UPDATE_PROB
#endif

#endif
"""

    for path in args.output:
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(content)


if __name__ == "__main__":
    main()
