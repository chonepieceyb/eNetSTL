#!/usr/bin/env python3
"""
NN-eBPF 数据集分析和展示脚本
用于详细分析和可视化网络入侵检测数据集
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import json
from collections import Counter
import os

# 设置中文字体
plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

class NNeBPFDatasetAnalyzer:
    def __init__(self, base_path):
        self.base_path = Path(base_path)
        self.dataset_path = self.base_path / "dataset"
        self.dataset_instance_path = self.base_path / "dataset-instance"

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
            "最大包长度", "最大时间间隔", "最小包长度",
            "目标端口", "头部总长度", "包数量"
        ]

        for i, (name, values) in enumerate(zip(feature_names, self.data.T)):
            print(f"   • {name}:")
            print(f"     - 均值: {np.mean(values):.2f}")
            print(f"     - 标准差: {np.std(values):.2f}")
            print(f"     - 最小值: {np.min(values):.2f}")
            print(f"     - 最大值: {np.max(values):.2f}")
            print(f"     - 中位数: {np.median(values):.2f}")

    def visualize_feature_distribution(self):
        """可视化特征分布"""
        print("\n📈 生成特征分布图...")

        feature_names = [
            "最大包长度", "最大时间间隔", "最小包长度",
            "目标端口", "头部总长度", "包数量"
        ]

        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        axes = axes.flatten()

        for i, (name, ax) in enumerate(zip(feature_names, axes)):
            # 分别绘制正常和攻击流量的分布
            normal_data = self.data[self.labels == 0, i]
            attack_data = self.data[self.labels == 1, i]

            ax.hist(normal_data, alpha=0.7, label='正常流量', bins=50, density=True)
            ax.hist(attack_data, alpha=0.7, label='攻击流量', bins=50, density=True)
            ax.set_title(f'{name}分布')
            ax.set_xlabel(name)
            ax.set_ylabel('密度')
            ax.legend()
            ax.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(self.base_path / 'feature_distribution.png', dpi=300, bbox_inches='tight')
        print("✅ 特征分布图已保存: feature_distribution.png")

    def visualize_correlation_matrix(self):
        """可视化特征相关性矩阵"""
        print("\n🔗 生成特征相关性矩阵...")

        # 创建 DataFrame
        feature_names = [
            "最大包长度", "最大时间间隔", "最小包长度",
            "目标端口", "头部总长度", "包数量"
        ]
        df = pd.DataFrame(self.data, columns=feature_names)
        df['标签'] = self.labels

        # 计算相关性矩阵
        corr_matrix = df.corr()

        # 绘制热力图
        plt.figure(figsize=(12, 10))
        sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', center=0,
                   square=True, fmt='.2f', cbar_kws={'shrink': 0.8})
        plt.title('特征相关性矩阵')
        plt.tight_layout()
        plt.savefig(self.base_path / 'correlation_matrix.png', dpi=300, bbox_inches='tight')
        print("✅ 相关性矩阵图已保存: correlation_matrix.png")

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

                total_files += len(files)
            else:
                print(f"❌ 路径不存在: {path}")

        print(f"\n📊 总计: {total_files} 个数据集文件")

    def analyze_attack_types(self):
        """分析攻击类型"""
        print("\n🎯 攻击类型分析...")

        attack_path = self.dataset_instance_path / "intrusion"
        if not attack_path.exists():
            print("❌ 攻击数据目录不存在")
            return

        attack_types = [d for d in attack_path.iterdir() if d.is_dir()]
        print(f"发现 {len(attack_types)} 种攻击类型:")

        for attack_type in attack_types:
            print(f"\n🔥 {attack_type.name.upper()} 攻击:")

            # 查找相关文件
            py_files = list(attack_type.rglob("*.py"))
            sh_files = list(attack_type.rglob("*.sh"))

            if py_files:
                print(f"   • Python 脚本:")
                for py_file in py_files:
                    print(f"     - {py_file.name}")

            if sh_files:
                print(f"   • Shell 脚本:")
                for sh_file in sh_files:
                    print(f"     - {sh_file.name}")

    def analyze_normal_traffic(self):
        """分析正常流量类型"""
        print("\n✅ 正常流量类型分析...")

        normal_path = self.dataset_instance_path / "normal"
        if not normal_path.exists():
            print("❌ 正常流量目录不存在")
            return

        normal_types = [d for d in normal_path.iterdir() if d.is_dir()]
        print(f"发现 {len(normal_types)} 种正常流量类型:")

        for normal_type in normal_types:
            print(f"\n🌐 {normal_type.name.upper()} 流量:")

            # 查找相关文件
            py_files = list(normal_type.rglob("*.py"))
            sh_files = list(normal_type.rglob("*.sh"))

            if py_files:
                print(f"   • Python 脚本:")
                for py_file in py_files:
                    print(f"     - {py_file.name}")

            if sh_files:
                print(f"   • Shell 脚本:")
                for sh_file in sh_files:
                    print(f"     - {sh_file.name}")

    def generate_summary_report(self):
        """生成数据集摘要报告"""
        print("\n📋 生成数据集摘要报告...")

        report = {
            "数据集基本信息": {
                "样本数量": int(len(self.data)),
                "特征数量": int(self.data.shape[1]),
                "正常样本数": int(np.sum(self.labels == 0)),
                "攻击样本数": int(np.sum(self.labels == 1)),
                "正常比例": float(np.sum(self.labels == 0) / len(self.labels)),
                "攻击比例": float(np.sum(self.labels == 1) / len(self.labels))
            },
            "特征统计": {
                feature_names[i]: {
                    "均值": float(np.mean(self.data[:, i])),
                    "标准差": float(np.std(self.data[:, i])),
                    "最小值": float(np.min(self.data[:, i])),
                    "最大值": float(np.max(self.data[:, i])),
                    "中位数": float(np.median(self.data[:, i]))
                }
                for i in range(self.data.shape[1])
            }
        }

        # 保存报告
        with open(self.base_path / 'dataset_summary.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        print("✅ 数据集摘要报告已保存: dataset_summary.json")

        # 打印摘要
        print("\n📊 数据集摘要:")
        print(f"   • 总样本数: {report['数据集基本信息']['样本数量']:,}")
        print(f"   • 正常样本: {report['数据集基本信息']['正常样本数']:,} ({report['数据集基本信息']['正常比例']:.1%})")
        print(f"   • 攻击样本: {report['数据集基本信息']['攻击样本数']:,} ({report['数据集基本信息']['攻击比例']:.1%})")

    def run_full_analysis(self):
        """运行完整的数据集分析"""
        print("🚀 开始 NN-eBPF 数据集完整分析...")
        print("=" * 60)

        # 加载数据集
        if not self.load_main_dataset():
            return False

        # 基本统计分析
        self.analyze_basic_stats()

        # 可视化分析
        self.visualize_feature_distribution()
        self.visualize_correlation_matrix()

        # 数据集实例分析
        self.analyze_dataset_instances()

        # 攻击类型分析
        self.analyze_attack_types()

        # 正常流量分析
        self.analyze_normal_traffic()

        # 生成报告
        self.generate_summary_report()

        print("\n✅ 数据集分析完成!")
        print("=" * 60)

        return True

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
            print("   • feature_distribution.png - 特征分布图")
            print("   • correlation_matrix.png - 相关性矩阵图")
            print("   • dataset_summary.json - 数据集摘要报告")
        else:
            print("❌ 分析失败")
            sys.exit(1)

    except Exception as e:
        print(f"❌ 分析过程中出现错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()