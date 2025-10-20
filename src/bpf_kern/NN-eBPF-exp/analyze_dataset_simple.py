#!/usr/bin/env python3
"""
NN-eBPF 数据集分析和展示脚本 (简化版，不依赖额外库)
用于详细分析网络入侵检测数据集
"""

import numpy as np
import json
from pathlib import Path
from collections import Counter
import os

class NNeBPFDatasetAnalyzer:
    def __init__(self, base_path):
        self.base_path = Path(base_path)
        self.dataset_path = self.base_path / "dataset"
        self.dataset_instance_path = self.base_path / "dataset-instance"
        self.data = None
        self.labels = None

    def load_main_dataset(self):
        """加载主要的数据集文件"""
        print("📊 加载主要数据集...")

        # 加载特征数据
        data_path = self.dataset_path / "reproduction-xdp-data.npy"
        if data_path.exists():
            self.data = np.load(data_path)
            print(f"✅ 特征数据加载成功: {self.data.shape}")
        else:
            print(f"❌ 特征数据文件不存在: {data_path}")
            return False

        # 加载标签数据
        label_path = self.dataset_path / "reproduction-xdp-label.npy"
        if label_path.exists():
            self.labels = np.load(label_path, allow_pickle=True)
            print(f"✅ 标签数据加载成功: {self.labels.shape}")
        else:
            print(f"❌ 标签数据文件不存在: {label_path}")
            return False

        return True

    def analyze_basic_stats(self):
        """分析基本统计信息"""
        print("\n🔍 基本统计分析...")

        # 数据形状
        n_samples, n_features = self.data.shape
        print(f"📈 数据集规模:")
        print(f"   • 样本数量: {n_samples:,}")
        print(f"   • 特征数量: {n_features}")
        print(f"   • 数据大小: {self.data.nbytes / 1024 / 1024:.2f} MB")

        # 标签分布
        unique_labels, counts = np.unique(self.labels, return_counts=True)
        print(f"\n📋 标签分布:")
        total = len(self.labels)
        for label, count in zip(unique_labels, counts):
            percentage = count / total * 100
            label_name = "正常流量" if label == 0 else "攻击流量"
            print(f"   • {label_name} (标签 {label}): {count:,} 样本 ({percentage:.1f}%)")

        # 特征统计
        print(f"\n📊 特征统计信息:")
        feature_names = [
            "最大包长度 (max_packet_length)",
            "最大时间间隔 (max_duration)",
            "最小包长度 (min_packet_length)",
            "目标端口 (dst_port)",
            "头部总长度 (header_length)",
            "包数量 (num_packet)"
        ]

        for i, (name, values) in enumerate(zip(feature_names, self.data.T)):
            print(f"   • 特征 {i+1}: {name}")
            print(f"     - 均值: {np.mean(values):.2f}")
            print(f"     - 标准差: {np.std(values):.2f}")
            print(f"     - 最小值: {np.min(values):.2f}")
            print(f"     - 最大值: {np.max(values):.2f}")
            print(f"     - 中位数: {np.median(values):.2f}")
            print(f"     - 25%分位数: {np.percentile(values, 25):.2f}")
            print(f"     - 75%分位数: {np.percentile(values, 75):.2f}")

    def analyze_feature_differences(self):
        """分析正常和攻击流量的特征差异"""
        print("\n🎯 正常 vs 攻击流量特征差异分析...")

        feature_names = [
            "最大包长度", "最大时间间隔", "最小包长度",
            "目标端口", "头部总长度", "包数量"
        ]

        normal_data = self.data[self.labels == 0]
        attack_data = self.data[self.labels == 1]

        print(f"\n📊 特征对比分析:")
        for i, name in enumerate(feature_names):
            normal_mean = np.mean(normal_data[:, i])
            attack_mean = np.mean(attack_data[:, i])
            normal_std = np.std(normal_data[:, i])
            attack_std = np.std(attack_data[:, i])

            # 计算差异倍数
            if attack_std > 0 and normal_std > 0:
                diff_ratio = abs(attack_mean - normal_mean) / ((normal_std + attack_std) / 2)
                significance = "🔥" if diff_ratio > 2 else "⚡" if diff_ratio > 1 else "📊"
            else:
                diff_ratio = 0
                significance = "📊"

            print(f"   {significance} {name}:")
            print(f"     正常流量: 均值={normal_mean:.2f}, 标准差={normal_std:.2f}")
            print(f"     攻击流量: 均值={attack_mean:.2f}, 标准差={attack_std:.2f}")
            print(f"     差异倍数: {diff_ratio:.2f}")

    def analyze_dataset_instances(self):
        """分析数据集实例结构"""
        print("\n📂 数据集实例结构分析...")

        # 统计各类数据集
        categories = {
            "正常流量": self.dataset_instance_path / "normal",
            "攻击流量": self.dataset_instance_path / "intrusion"
        }

        total_files = 0
        for category, path in categories.items():
            if path.exists():
                files = list(path.rglob("*"))
                py_files = list(path.rglob("*.py"))
                sh_files = list(path.rglob("*.sh"))
                txt_files = list(path.rglob("*.txt"))

                print(f"\n📁 {category} ({path.name}):")
                print(f"   • 总文件数: {len(files)}")
                print(f"   • Python 脚本: {len(py_files)}")
                print(f"   • Shell 脚本: {len(sh_files)}")
                print(f"   • 文本文件: {len(txt_files)}")

                # 分析子目录
                subdirs = [d for d in path.iterdir() if d.is_dir()]
                for subdir in subdirs:
                    sub_files = list(subdir.rglob("*"))
                    print(f"     - {subdir.name}: {len(sub_files)} 文件")
                    # 统计文件类型
                    sub_py = list(subdir.rglob("*.py"))
                    sub_sh = list(subdir.rglob("*.sh"))
                    if sub_py or sub_sh:
                        if sub_py:
                            print(f"       Python: {[f.name for f in sub_py]}")
                        if sub_sh:
                            print(f"       Shell: {[f.name for f in sub_sh]}")

                total_files += len(files)
            else:
                print(f"❌ 路径不存在: {path}")

        print(f"\n📊 总计: {total_files} 个数据集文件")

    def analyze_attack_types_in_detail(self):
        """详细分析攻击类型"""
        print("\n🎯 攻击类型详细分析...")

        attack_path = self.dataset_instance_path / "intrusion"
        if not attack_path.exists():
            print("❌ 攻击数据目录不存在")
            return

        attack_types = [d for d in attack_path.iterdir() if d.is_dir()]
        print(f"发现 {len(attack_types)} 种攻击类型:")

        attack_info = {}
        for attack_type in attack_types:
            print(f"\n🔥 {attack_type.name.upper()} 攻击:")

            # 查找相关文件
            py_files = list(attack_type.rglob("*.py"))
            sh_files = list(attack_type.rglob("*.sh"))
            txt_files = list(attack_type.rglob("*.txt"))

            attack_info[attack_type.name] = {
                "python_scripts": [f.name for f in py_files],
                "shell_scripts": [f.name for f in sh_files],
                "total_files": len(py_files) + len(sh_files) + len(txt_files)
            }

            if py_files:
                print(f"   • Python 脚本 ({len(py_files)} 个):")
                for py_file in py_files:
                    print(f"     - {py_file.name}")
                    # 尝试读取脚本内容摘要
                    try:
                        with open(py_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                            lines = content.split('\n')[:5]  # 前5行
                            print(f"       摘要: {' | '.join(lines[:2])}")
                    except:
                        print(f"       [无法读取文件]")

            if sh_files:
                print(f"   • Shell 脚本 ({len(sh_files)} 个):")
                for sh_file in sh_files:
                    print(f"     - {sh_file.name}")

        return attack_info

    def analyze_normal_traffic_in_detail(self):
        """详细分析正常流量类型"""
        print("\n✅ 正常流量类型详细分析...")

        normal_path = self.dataset_instance_path / "normal"
        if not normal_path.exists():
            print("❌ 正常流量目录不存在")
            return

        normal_types = [d for d in normal_path.iterdir() if d.is_dir()]
        print(f"发现 {len(normal_types)} 种正常流量类型:")

        normal_info = {}
        for normal_type in normal_types:
            print(f"\n🌐 {normal_type.name.upper()} 流量:")

            # 查找相关文件
            py_files = list(normal_type.rglob("*.py"))
            sh_files = list(normal_type.rglob("*.sh"))
            txt_files = list(normal_type.rglob("*.txt"))

            normal_info[normal_type.name] = {
                "python_scripts": [f.name for f in py_files],
                "shell_scripts": [f.name for f in sh_files],
                "total_files": len(py_files) + len(sh_files) + len(txt_files)
            }

            if py_files:
                print(f"   • Python 脚本 ({len(py_files)} 个):")
                for py_file in py_files:
                    print(f"     - {py_file.name}")
                    # 尝试读取脚本内容摘要
                    try:
                        with open(py_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                            lines = content.split('\n')[:3]  # 前3行
                            if lines[0].strip():
                                print(f"       功能: {lines[0].strip()}")
                    except:
                        print(f"       [无法读取文件]")

            if sh_files:
                print(f"   • Shell 脚本 ({len(sh_files)} 个):")
                for sh_file in sh_files:
                    print(f"     - {sh_file.name}")

            # 检查是否有特殊的配置文件
            if txt_files:
                special_files = [f for f in txt_files if f.name not in ['timestamp.txt']]
                if special_files:
                    print(f"   • 配置文件 ({len(special_files)} 个):")
                    for txt_file in special_files:
                        print(f"     - {txt_file.name}")

        return normal_info

    def generate_text_summary(self):
        """生成文本格式的数据集摘要"""
        print("\n📋 生成数据集文本摘要...")

        summary = f"""
NN-eBPF 数据集分析报告
======================

数据集基本信息:
- 样本数量: {len(self.data):,}
- 特征数量: {self.data.shape[1]}
- 正常样本: {np.sum(self.labels == 0):,} ({np.sum(self.labels == 0) / len(self.labels) * 100:.1f}%)
- 攻击样本: {np.sum(self.labels == 1):,} ({np.sum(self.labels == 1) / len(self.labels) * 100:.1f}%)

特征列表:
1. 最大包长度 (max_packet_length) - 流中最大数据包的字节数
2. 最大时间间隔 (max_duration) - 数据包间最大时间间隔(纳秒)
3. 最小包长度 (min_packet_length) - 流中最小数据包的字节数
4. 目标端口 (dst_port) - TCP 目标端口号
5. 头部总长度 (header_length) - TCP 头部总长度累积(字节)
6. 包数量 (num_packet) - 流中数据包总数

数据集用途:
- 网络入侵检测模型训练
- 异常流量识别
- eBPF 神经网络推理验证

特征工程说明:
- 所有特征都可在 eBPF 环境中实时计算
- 特征值反映了网络流的统计特性
- 适用于基于流的网络行为分析
"""

        # 保存摘要
        with open(self.base_path / 'dataset_summary.txt', 'w', encoding='utf-8') as f:
            f.write(summary)

        print("✅ 数据集文本摘要已保存: dataset_summary.txt")
        print(summary)

    def run_full_analysis(self):
        """运行完整的数据集分析"""
        print("🚀 开始 NN-eBPF 数据集完整分析...")
        print("=" * 60)

        # 加载数据集
        if not self.load_main_dataset():
            return False

        # 基本统计分析
        self.analyze_basic_stats()

        # 特征差异分析
        self.analyze_feature_differences()

        # 数据集实例分析
        self.analyze_dataset_instances()

        # 攻击类型详细分析
        attack_info = self.analyze_attack_types_in_detail()

        # 正常流量详细分析
        normal_info = self.analyze_normal_traffic_in_detail()

        # 生成文本摘要
        self.generate_text_summary()

        # 生成详细 JSON 报告
        self.generate_json_report(attack_info, normal_info)

        print("\n✅ 数据集分析完成!")
        print("=" * 60)

        return True

    def generate_json_report(self, attack_info, normal_info):
        """生成详细的 JSON 报告"""
        print("\n📋 生成详细 JSON 报告...")

        report = {
            "数据集基本信息": {
                "样本数量": int(len(self.data)),
                "特征数量": int(self.data.shape[1]),
                "正常样本数": int(np.sum(self.labels == 0)),
                "攻击样本数": int(np.sum(self.labels == 1)),
                "正常比例": float(np.sum(self.labels == 0) / len(self.labels)),
                "攻击比例": float(np.sum(self.labels == 1) / len(self.labels)),
                "数据大小_MB": float(self.data.nbytes / 1024 / 1024)
            },
            "特征统计": {
                f"特征_{i+1}": {
                    "名称": name,
                    "均值": float(np.mean(self.data[:, i])),
                    "标准差": float(np.std(self.data[:, i])),
                    "最小值": float(np.min(self.data[:, i])),
                    "最大值": float(np.max(self.data[:, i])),
                    "中位数": float(np.median(self.data[:, i])),
                    "25%分位数": float(np.percentile(self.data[:, i], 25)),
                    "75%分位数": float(np.percentile(self.data[:, i], 75))
                }
                for i, name in enumerate([
                    "最大包长度", "最大时间间隔", "最小包长度",
                    "目标端口", "头部总长度", "包数量"
                ])
            },
            "攻击类型": attack_info,
            "正常流量类型": normal_info,
            "数据集文件统计": {
                "总文件数": len(list(self.dataset_instance_path.rglob("*"))),
                "Python脚本数": len(list(self.dataset_instance_path.rglob("*.py"))),
                "Shell脚本数": len(list(self.dataset_instance_path.rglob("*.sh"))),
                "文本文件数": len(list(self.dataset_instance_path.rglob("*.txt")))
            }
        }

        # 保存报告
        with open(self.base_path / 'dataset_summary.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        print("✅ 详细 JSON 报告已保存: dataset_summary.json")

def main():
    """主函数"""
    import sys

    # 获取脚本所在目录
    script_dir = Path(__file__).parent
    analyzer = NNeBPFDatasetAnalyzer(script_dir)

    try:
        success = analyzer.run_full_analysis()
        if success:
            print(f"\n🎉 分析完成！结果保存在: {script_dir}")
            print("📁 生成的文件:")
            print("   • dataset_summary.txt - 数据集文本摘要")
            print("   • dataset_summary.json - 详细数据报告")
        else:
            print("❌ 分析失败")
            sys.exit(1)

    except Exception as e:
        print(f"❌ 分析过程中出现错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()