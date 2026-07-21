from dataclasses import dataclass, field
from typing import List, Dict, Any

# 严重程度排序：数值越小越严重
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

@dataclass
class Finding:
    """安全检测发现项"""
    category:       str          # 检测类别
    title:          str          # 发现项标题
    severity:       str          # 严重程度：CRITICAL | HIGH | MEDIUM | LOW | INFO
    description:    str          # 问题描述
    details:        List[str] = field(default_factory=list)  # 详细信息列表
    recommendation: str = ""     # 修复建议
    risk_score:     int = 0      # 风险扣分（从100分中扣除）
    references:     List[str] = field(default_factory=list)  # 参考链接

@dataclass
class ScanResult:
    """扫描结果汇总"""
    domain:    str              # 目标域名
    scan_time: str              # 扫描时间
    dc_ip:     str              # 域控制器IP
    findings:  List[Finding]    = field(default_factory=list)  # 所有发现项
    stats:     Dict[str, Any]   = field(default_factory=dict)  # 统计数据

    @property
    def total_score(self) -> int:
        """计算总分（满分100，按风险扣分）"""
        return max(0, 100 - sum(f.risk_score for f in self.findings))

    @property
    def risk_level(self) -> str:
        """根据总分判定整体风险等级"""
        s = self.total_score
        if s >= 80: return "LOW"
        if s >= 60: return "MEDIUM"
        if s >= 40: return "HIGH"
        return "CRITICAL"

    def findings_by_severity(self) -> List[Finding]:
        """按严重程度排序的发现项列表"""
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 5))

    def counts(self) -> Dict[str, int]:
        """按严重程度统计数量"""
        c: Dict[str, int] = {}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c
