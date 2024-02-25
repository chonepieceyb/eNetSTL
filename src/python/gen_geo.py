import argparse
from functools import reduce
from scipy import stats

from utils import *

DEFAULT_MAX_GEOSAMPLING_SIZE = 1024
DEFAULT_GEO_CNT_CAP = (1 << 31) - 1
DEFAULT_GEO_CNT_TYPE = "uint8_t"


def gen_geo_cnts(prob, max_geosampling_size, bound):
    geo_cnts = []
    geo_var = stats.geom(prob)
    capped_cnt = 0
    for _ in range(max_geosampling_size):
        geo_cnt = geo_var.rvs()
        if geo_cnt > bound:
            capped_cnt += 1
            geo_cnt = bound
        geo_cnts.append(geo_cnt)
    return geo_cnts, capped_cnt


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
    parser.add_argument(
        "--geo-cnt-cap",
        type=int,
        default=DEFAULT_GEO_CNT_CAP,
        help=f"cap of geo cnt; defaults to {DEFAULT_GEO_CNT_CAP}",
    )
    parser.add_argument(
        "--geo-cnt-type",
        default=DEFAULT_GEO_CNT_TYPE,
        help=f"type of geo cnt; defaults to {DEFAULT_GEO_CNT_TYPE}",
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
        geo_cnts_per_cpu, capped_cnt = reduce(
            lambda prev, curr: ([*prev[0], curr[0]], prev[1] + curr[1]),
            map(
                lambda _: gen_geo_cnts(
                    prob, args.max_geosampling_size, args.geo_cnt_cap
                ),
                range(args.cpus),
            ),
            ([], 0),
        )
        if capped_cnt:
            geo_cnts_size = len(geo_cnts_per_cpu[0]) * args.cpus
            print(
                f"{capped_cnt / geo_cnts_size * 100:.2f}% ({capped_cnt} / {geo_cnts_size}) "
                f"element(s) are capped at {args.geo_cnt_cap} for {prob_percent}% update probability"
            )
        content += f"""
#{'el' if i else ''}if SK_NITRO_UPDATE_PROB_PERCENT == {prob_percent}
{args.geo_cnt_type} GEO_SAMPLING_POOL[ONLINE_CPU_NUM][MAX_GEOSAMPLING_SIZE] = {{
"""
        for geo_cnts in geo_cnts_per_cpu:
            content += "\t{" + ", ".join(map(str, geo_cnts)) + "},\n"
        content += "};"
    content += """
#else
#error unsupported SK_NITRO_UPDATE_PROB_PERCENT
#endif

#endif
"""

    for path in args.output:
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(content)


if __name__ == "__main__":
    main()
