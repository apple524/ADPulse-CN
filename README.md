# ADPulse — Active Directory Security Scanner

<p align="left">
  <img src="https://github.com/dievus/ADPulse/blob/main/images/image.png"/>
</p>

ADPulse是一款开源的Active Directory安全审计工具，它通过LDAP(S)连接到域控制器，运行35项自动化安全检查，并以控制台、JSON和HTML格式生成详细报告。

它专为需要快速、只读评估AD（活动目录）配置错误和攻击面的IT管理员、渗透测试人员和安全团队设计。

如果您希望设置自己的易受攻击的域控制器以进行测试，本文还包含了一个名为test_environment.ps1的PowerShell脚本。
---

## 功能特性 (Features)

### 安全检查项目 (共 35 项)

| # | 检查项目 | 具体描述 |
|---|-------|-------------|
| 1 | **密码策略 (Password Policy)** | 最小密码长度、密码历史留存、密码复杂度、账户锁定阈值、可逆加密、细粒度密码策略（PSO） |
| 2 | **高权限账户** | 域管理员、企业管理员、架构管理员等敏感组成员；长期未使用账户、永不过期密码、描述字段内置明文密码、内置管理员状态、krbtgt 账户存续时长 |
| 3 | **Kerberos 风险** | 可 Kerberoast 攻击账户（用户对象绑定 SPN）、可 AS-REP Roast 攻击账户、仅支持 DES 加密、高风险目标（adminCount=1 + 绑定 SPN + 密码永不过期） |
| 4 | **无约束委派** | 配置无约束 Kerberos 委派权限的非域控计算机与用户账户 |
| 5 | **约束委派** | 配置协议转换（S4U2Self）与标准约束委派目标的账户 |
| 6 | **ADCS / PKI 证书服务** | ESC1、ESC2、ESC3、ESC6、ESC8、ESC9、ESC10、ESC11、ESC13、ESC15 各类证书漏洞；弱密钥长度、证书注册权限枚举 |
| 7 | **域信任关系** | 未启用 SID 过滤的双向信任、林信任、外部域信任 |
| 8 | **账户规范管理** | 长期闲置用户 / 计算机账户、从未登录账户、无需密码登录标记、单账户可逆加密、老旧密码、重复 SPN |
| 9 | **协议安全配置** | LDAP 签名 / 通道绑定、域控制器操作系统版本、域 / 林功能级别、NTLMv1/WDigest 风险提示 |
| 10 | **组策略对象（GPO）** | 已禁用、孤立、未链接、空 GPO；GPO 数量过多风险 |
| 11 | **LAPS 本地管理员密码方案** | 旧版 LAPS 与 Windows 原生 LAPS 架构检测；未配置 LAPS 密码的计算机 |
| 12 | **LAPS 覆盖覆盖率** | 所有非域控计算机中启用 LAPS 托管密码的占比统计 |
| 13 | **DNS 与基础设施** | DNS 泛域名记录、LLMNR/NetBIOS-NS 投毒风险提示 |
| 14 | **域控制器检测** | 单域控环境识别、老旧系统域控、FSMO 五大角色、只读域控（RODC）密码复制策略 |
| 15 | **ACL 权限控制** | ESC4、ESC5、ESC7 证书权限漏洞；普通主体拥有 DCSync 权限；受保护用户组、委派相关 ACL |
| 16 | **可选扩展检测** | AD 回收站、特权访问管理（PAM） |
| 17 | **复制健康状态** | 站点数量、站点链接复制间隔、nTDSDSA 复制对象 |
| 18 | **服务账户** | 托管组服务账户（gMSA）部署情况、普通用户型服务账户、拥有管理员权限（adminCount=1）的服务账户 |
| 19 | **加固配置杂项** | 计算机账户创建配额、墓碑生存期、架构管理员 / 企业管理员成员、来宾账户、审计策略指引 |
| 20 | **淘汰操作系统** | 已启用账户绑定停止支持（EOL）Windows 系统主机 |
| 21 | **老旧不安全协议** | SMBv1 检测、强制 SMB 签名、空会话探测（实时网络探测） |
| 22 | **Exchange 相关风险** | Exchange Windows Permissions 组（PrivExchange / CVE-2019-0686）、Exchange 可信子系统 |
| 23 | **受保护管理员账户** | adminCount=1 管理员全量盘点：孤立账户、禁用幽灵账户、长期闲置管理员 |
| 24 | **描述字段明文密码** | 关键词匹配检测用户、管理员、计算机描述字段内存储的明文凭证 |
| 25 | **GPP 组策略密码 cpassword（MS14-025）** | 遍历 SYSVOL 内组策略首选项 XML 文件，提取 cpassword 字段并使用微软公开 AES 密钥解密 |
| 26 | **AdminSDHolder 权限列表** | 读取 `CN=AdminSDHolder` 二进制 DACL，标记拥有写入权限的非特权主体；该权限每 60 分钟通过 SDProp 自动同步至所有受保护管理员账户 |
| 27 | **	SID 历史注入** | 检测配置 `sIDHistory` 的账户；若注入 SID 映射至域管理员、企业管理员等高权限组，标记为严重风险 |
| 28 | **影子凭证（Shadow Credentials）** | 标记用户 / 计算机对象上异常 `msDS-KeyCredentialLink` 条目，攻击者可无需账户密码，通过证书认证登录 |
| 29 | **RC4 老旧 Kerberos 加密** | 检测服务账户、域控、管理员账户的` msDS-SupportedEncryptionTypes`，识别仍允许 RC4-HMAC 加密的对象（攻击者常用该弱加密类型离线爆破） |
| 30 | **高权限组内外部安全主体** | 枚举外部安全主体容器 `CN=ForeignSecurityPrincipals`，标记可信域外主体加入域管理员、备份操作员等敏感本地组的情况 |
| 31 | **兼容 Windows 2000 访问权限** | 检测该组是否包含 `Everyone` 或 `Anonymous Logon` 用户，此配置允许全网未认证主体枚举 SAMR/LSARPC 信息 |
| 32 | **高危约束委派目标** | 交叉比对委派目标与域控主机名，标记可向域控  (`ldap/`, `cifs/`, `host/`, `gc/`, `krbtgt/`)等高价值服务类委派权限的账户 |
| 33 | **孤立 AD 子网** | 查找未绑定站点对象 `siteObject` 的子网，客户端会随机分配域控，可能导致认证流量跨广域网传输 |
| 34 | **老旧 FRS SYSVOL 复制** | 检测 SYSVOL 是否仍使用已淘汰的文件复制服务（FRS）而非 DFSR，标记迁移中断状态 |
| 35 | **域 / 域控反向约束委派（RBCD）** | 检测域根命名上下文与所有域控计算机对象的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 该配置会赋予指定主体通过 S4U2Proxy 获取域管理员权限 |

### 报告输出

- **控制台** — 彩色终端输出，直观展示高危漏洞与核心指标
- **JSON** — 机器可读格式，可对接 SIEM、工单系统、自定义可视化面板
- **HTML** — 独立深色主题报告，支持折叠模块、风险等级标签、数据统计卡片、证书模板清单

### 风险评分机制

所有检测结果均会扣除对应风险分值，初始满分**100 分**：

| 得分区间| 风险等级 | 说明 |
|-------|-----------|---------|
| 80–100 | 低风险 | 安全状态良好，仅存在轻微问题|
| 60–79 | 中风险 | 存在明显安全缺陷，需尽快修复 |
| 40–59 | 高风险	 | 存在大量高危漏洞 |
| 0–39 | 严重风险 | 安全隐患极其严重，需立即处置 |

---

## 运行环境要求

- Python 3.8 及以上版本
- 网络可访问域控制器（636 端口 LDAPS、389 端口 LDAP、445 端口 SMB 探测）
- 拥有域读取权限的域账户（绝大多数检测无需管理员权限）
- 检测项 25（GPP/cpassword）依赖：扫描主机可访问 SYSVOL 共享（Windows 直接 UNC 访问；Linux/macOS 需通过 Samba 挂载）

### Python 依赖库

```
ldap3>=2.9
colorama>=0.4.6
dnspython>=2.4.0
pycryptodome
weasyprint
```

---

## 安装步骤

```bash
# Clone the repository
git clone https://github.com/yourorg/adpulse.git
cd adpulse

# 推荐：创建虚拟环境隔离依赖
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows

# 安装全部依赖包
pip install -r requirements.txt
```

---

## 使用说明

### 基础扫描命令

```bash
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!'
```

工具通过 DNS 自动解析域控制器 IP，默认生成控制台、JSON、HTML 三种报告，统一输出至 `Reports/` 文件夹。

### 指定目标域控制器 IP

```bash
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!' --dc-ip 10.0.0.1
```

### 自定义报告输出格式

```bash
# 仅控制台输出
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!' --report console

# 仅导出JSON
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!' --report json

# 仅导出HTML报告
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!' --report html

# 全部格式（默认配置）
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!' --report all
```

### 自定义报告存储目录

```bash
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!' --output-dir /tmp/scans
```

Reports are written to `<output-dir>/Reports/`.

### 关闭控制台彩色输出

```bash
python ADPulse.py --domain corp.local --user jsmith --password 'P@ssw0rd!' --no-color
```

### 完整参数对照表

| 参数 | 是否必填 | 默认值 | 说明 |
|----------|----------|---------|-------------|
| `--domain` | Yes | — | 目标活动目录域名（例：`corp.local`）|
| `--user` | Yes | — | 域登录用户名 |
| `--password` | Yes | — | 域账户密码 |
| `--hash` | 无密码时必填 | — | 域账户 NTLM 哈希值 |
| `--dc-ip` | No | DNS 自动解析 | 域控制器指定 IP 地址 |
| `--report` | No | `all` | 报告格式: `console`, `json`, `html`, or `all` |
| `--output-dir` | No | `.` | Reports 文件夹的存储路径 `Reports/`  |
| `--no-color` | No | `false` | 关闭终端彩色打印 |

---

## 项目文件结构

```
adpulse/
├── ADPulse.py          # 程序入口：参数解析、扫描流程调度
├── connector.py        # LDAP(S) 连接封装、查询工具、SID 解析
├── checks.py           # 全部35项安全检测逻辑
├── models.py           # 漏洞结果、扫描结果数据模型
├── report.py           # 控制台、JSON、HTML 报告生成模块
├── __init__.py         # 包基础信息
└── requirements.txt    # Python 依赖清单
```

---

## 工具工作原理

1. **建立连接** — ADPulse 通过 636 端口 LDAPS 建立连接，连接失败自动降级至 389 端口 LDAP；同时支持 NTLM、简易绑定两种认证方式。
2. **执行扫描** — 依次调用 35 项检测函数，通过 LDAP 查询 AD 数据；部分检测附加辅助操作：对发现主机执行轻量网络探测（SMBv1、SMB 签名、空会话）、遍历 SYSVOL 文件检测 GPP 明文凭证、解析二进制 DACL 完成权限审计。
3. **风险打分** — 每条漏洞分配对应风险等级（严重→提示）与扣分值，最终总分计算公式：`max(0, 100 - 总扣分值)`。
4. **生成报告** — 结果打印至终端，同时可选导出 JSON 与独立 HTML 文件。

全部操作均为**只读**,ADPulse 不会修改任何 AD 对象、组关系、组策略或权限列表。

---

## 安全使用注意事项

- 工具运行需要合法域账号，账号密码需加密存储与传输。
- SMB 探测模块会向目标主机 445 端口发送原始 TCP 数据包，执行网络层面测试前务必获得授权。
- GPP/cpassword 检测仅读取 SYSVOL 文件，不会修改、删除任何文件。
- HTML 报告包含敏感数据（账户名、组成员、SPN、解密后的 GPP 密码），所有报告文件均需保密存储。
- 请在目标网络内受信任、加固后的工作站运行本工具。

---

## 工具局限性

- **仅注册表存储的配置** — NTLMv1 (`LmCompatibilityLevel`), WDigest (`UseLogonCredential`), LDAP 签名 (`ldapServerIntegrity`), 通道绑定 (`ldapEnforceChannelBinding`) 无法通过 LDAP 读取，工具仅标记为人工复核项。
- **组策略内容解析限制** — 仅检测 GPO 元数据（启用状态、孤立、SYSVOL 路径、链接关系），除 cpassword 检测外不会解析 SYSVOL 内完整策略配置文件。
- **SYSVOL 访问依赖** — 检测项 25（GPP/cpassword）需要扫描主机文件系统访问 SYSVOL。Windows 原生支持 UNC 路径；Linux/macOS 需挂载 Samba 共享，无法访问时工具提示人工核查。
- **ADCS ESC8 检测** — 证书 Web 注册点检测需要网络可达 CA 的 `certsrv` 服务地址。
- **SMB 探测干扰** — 防火墙、主机安全策略拦截 445 端口会导致 SMBv1、SMB 签名、空会话检测出现漏报。
- **影子凭证区分困难** — Windows Hello for Business 合法创建的 `msDS-KeyCredentialLink` 条目同样会被扫描标记，需人工区分合法配置与攻击者植入凭证。
- **查询结果上限** — LDAP 单次查询最多返回 10000 条数据，超大型域可能需要多次扫描或调整域控查询上限。

---
