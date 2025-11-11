# ARP 攻击流量特征与 SIEM 检测规则

## 一、ARP 报文关键字段

### ARP 报文结构

**ARP Request（请求）:**

```
- Operation: ARP Request (1)
- SourceHwAddress: 请求者（发送方）MAC 地址
- SourceProtAddress: 请求者（发送方）IP 地址
- DstHwAddress: 目标 MAC 地址（通常为全0或广播地址，因为未知）
- DstProtAddress: 目标 IP 地址（被查询的主机 IP）
```

**ARP Reply（回复）:**

```
- Operation: ARP Reply (2)
- SourceHwAddress: 回复者（被请求方）MAC 地址
- SourceProtAddress: 回复者（被请求方）IP 地址
- DstHwAddress: 目标 MAC 地址（原请求者的 MAC 地址）
- DstProtAddress: 目标 IP 地址（原请求者的 IP 地址）
```

**注意**: 在 ARP Request 和 ARP Reply 中，Source 和 Dst 的含义是相反的：

- Request 中：Source = 请求者，Dst = 被请求者
- Reply 中：Source = 被请求者（回复者），Dst = 原请求者

### 以太网层字段

```
- SrcMAC: 源 MAC 地址
- DstMAC: 目标 MAC 地址（广播: ff:ff:ff:ff:ff:ff）
```

### ARP Reply 单播与广播在日志中的区别

**正常 ARP Reply（单播）:**

```
- 以太网层 DstMAC: 具体的 MAC 地址（原请求者的 MAC，如 aa:bb:cc:dd:ee:ff）
- ARP 层 DstHwAddress: 具体的 MAC 地址（原请求者的 MAC，如 aa:bb:cc:dd:ee:ff）
- ARP 层 DstProtAddress: 原请求者的 IP 地址
- 特征: 直接回复给请求者，一对一通信
```

**广播 ARP Reply（通常可疑，但某些场景下正常）:**

```
- 以太网层 DstMAC: ff:ff:ff:ff:ff:ff（广播地址）
- ARP 层 DstHwAddress: 00:00:00:00:00:00（全0，表示"未指定目标"）或 ff:ff:ff:ff:ff:ff（全F，较少见）
- ARP 层 DstProtAddress: 0.0.0.0 或原请求者的 IP
- 特征: 广播发送，所有设备都能收到
```

**全 0 vs 全 F 的区别:**

- **全 0 (00:00:00:00:00:00)**:

  - 含义: 表示"未知"或"未指定目标"
  - 常见场景: Gratuitous ARP（设备宣告自己的 IP-MAC 映射，不针对特定目标）
  - 用途: 更新网络中所有设备的 ARP 缓存表
  - 示例: 设备启动时发送，告知网络"我的 IP 是 X，MAC 是 Y"

- **全 F (ff:ff:ff:ff:ff:ff)**:
  - 含义: 以太网广播地址（在 ARP 层使用较少见）
  - 常见场景: 某些实现可能使用，但不符合标准 ARP 协议规范
  - 用途: 理论上等同于全 0，但实际使用较少
  - 注意: 在 ARP 层，全 F 的使用可能表示实现不规范或攻击行为

**检测建议:**

- 优先检查全 0（00:00:00:00:00:00），这是最常见的 Gratuitous ARP 特征
- 全 F（ff:ff:ff:ff:ff:ff）在 ARP 层出现时，应视为可疑（可能是不规范实现或攻击）
- 结合是否有对应 Request 来判断：无 Request + 全 0/全 F = 可疑的 Gratuitous ARP

**正常场景下的广播 ARP Reply:**

- 设备启动时的 Gratuitous ARP（宣告自己的 IP-MAC 映射）
- 某些网络设备的故障恢复机制
- 但频率应该很低，如果频繁出现则可能是攻击

**检测方法:**

- 检查 `DstMAC == "ff:ff:ff:ff:ff:ff"` 或 `DstHwAddress == "00:00:00:00:00:00"`
- 结合是否有对应的 ARP Request 来判断
- 正常单播回复：`DstMAC` 和 `DstHwAddress` 都是具体的 MAC 地址
- 可疑广播回复：`DstMAC == "ff:ff:ff:ff:ff:ff"` 且无对应 Request

### Gratuitous ARP 详解

**什么是 Gratuitous ARP？**

Gratuitous ARP（无偿 ARP）是一种特殊的 ARP 报文，设备主动发送 ARP 回复来宣告自己的 IP-MAC 映射，而不是响应某个 ARP 请求。

**关键特征:**

```
- Operation: ARP Reply (2)
- SourceProtAddress: 发送者自己的 IP（如 192.168.1.50）
- DstProtAddress: 也是发送者自己的 IP（192.168.1.50）
- SourceHwAddress: 发送者自己的 MAC 地址
- DstHwAddress: 00:00:00:00:00:00（全0，表示未指定目标）
- 以太网层 DstMAC: ff:ff:ff:ff:ff:ff（广播地址）
```

**正常用途:**

1. **设备启动时宣告:**

   - 设备启动后主动宣告自己的 IP-MAC 映射
   - 更新网络中其他设备的 ARP 缓存表
   - 通常发送 1-3 次，然后停止

2. **IP 地址变更时:**

   - 当设备获得新 IP 地址时（如 DHCP 分配）
   - 宣告新的 IP-MAC 映射
   - 通常发送 1-2 次

3. **故障恢复:**

   - 网络接口恢复后重新宣告
   - 某些网络设备的故障恢复机制

4. **IP 地址冲突检测:**
   - 设备在配置 IP 前发送 Gratuitous ARP
   - 如果收到回复，说明 IP 已被占用

**攻击场景:**

1. **ARP 欺骗攻击:**

   - 攻击者发送 Gratuitous ARP，声称自己是网关或其他设备
   - 更新目标设备的 ARP 缓存，将流量重定向到攻击者

2. **ARP 投毒:**

   - 频繁发送 Gratuitous ARP，持续污染 ARP 缓存
   - 保持攻击效果，防止 ARP 缓存过期

3. **MITM 攻击:**
   - 同时向网关和受害者发送 Gratuitous ARP
   - 实现双向流量劫持

**如何区分正常和攻击？**

| 特征            | 正常 Gratuitous ARP             | 攻击 Gratuitous ARP      |
| --------------- | ------------------------------- | ------------------------ |
| **频率**        | 低（设备启动/IP 变更时 1-3 次） | 高（频繁或周期性发送）   |
| **声称的 IP**   | 自己的合法 IP                   | 网关 IP 或其他设备的 IP  |
| **发送模式**    | 一次性或少量发送后停止          | 周期性重复或持续发送     |
| **IP-MAC 映射** | 与已知映射一致                  | 与已知映射冲突           |
| **时间特征**    | 发生在设备状态变化时            | 无设备状态变化却频繁发送 |

**检测要点:**

1. **频率检测:** 正常频率 < 5 次/小时/设备，攻击通常 > 10 次/小时
2. **IP 检测:** 检查是否声称网关 IP 或其他设备的 IP
3. **模式检测:** 检查是否周期性重复发送
4. **冲突检测:** 检查是否与已知 IP-MAC 映射冲突

---

## 二、各类 ARP 攻击流量特征

### 1. ARP 欺骗/ARP 毒化（ARP Spoofing/Poisoning）

#### 特征描述:reply

攻击者发送伪造的 ARP 回复，将合法 IP 地址映射到攻击者的 MAC 地址，从而污染目标设备的 ARP 缓存表。

**说明**: ARP 欺骗、ARP 毒化（ARP Poisoning）和 ARP 表投毒（ARP Cache Poisoning）本质上是同一种攻击技术的不同表述：

- **ARP 欺骗（ARP Spoofing）**: 强调"欺骗"行为，将流量重定向到攻击者
- **ARP 毒化（ARP Poisoning）**: 强调"污染"ARP 缓存表的行为
- **ARP 表投毒（ARP Cache Poisoning）**: 强调"持续污染"ARP 缓存表，通常指周期性重复发送以保持攻击效果

在实际检测中，我们主要关注攻击的行为特征（频率、模式、目标）而非术语差异。

#### 流量特征

| 特征项                          | 正常行为                              | 攻击行为                         | 检测阈值     |
| ------------------------------- | ------------------------------------- | -------------------------------- | ------------ |
| **ARP Reply 频率**              | 低（响应请求时）                      | 高（主动发送）                   | > 10 个/分钟 |
| **无对应 Request 的 ARP Reply** | 无（所有 Reply 都有对应 Request）     | 有（Gratuitous ARP）             | 出现即告警   |
| **IP-MAC 映射冲突**             | 无或有序切换（设备更换、DHCP 重分配） | 短时间内同一 IP 同时对应多个 MAC | 出现即告警   |
| **MAC 地址变化频率**            | 低                                    | 高                               | > 3 次/小时  |
| **ARP Reply 目标 MAC**          | 单播                                  | 广播或全 0                       | 出现即告警   |
| **周期性重复回复**              | 无                                    | 有（定时刷新，保持攻击效果）     | 周期 < 60 秒 |
| **固定目标重复攻击**            | 无                                    | 有（针对特定目标持续攻击）       | > 5 次/分钟  |

#### 检测规则

```yaml
规则名称: ARP_欺骗检测_IP_MAC冲突
描述: 检测同一 IP 地址对应多个不同 MAC 地址的情况（区分正常切换和攻击冲突）
条件:
  - 事件类型: ARP Reply
  - 时间窗口: 5 分钟
  - 聚合字段: SourceProtAddress
  - 统计: COUNT(DISTINCT SourceHwAddress)
  - 阈值: >
检测逻辑:
  # 关键：区分正常切换和攻击冲突
  1. 正常切换特征（不告警）:
    - 旧 MAC 停止发送 ARP Reply（在时间窗口内无新消息）
    - 新 MAC 才开始发送 ARP Reply
    - 切换时间间隔 > 30 秒
    - 旧 MAC 和新 MAC 不同时活跃

  2. 攻击冲突特征（告警）:
    - 多个不同 MAC 在短时间内（< 30秒）同时声称拥有同一 IP
    - 多个 MAC 在时间窗口内都有活跃的 ARP Reply
    - 旧 MAC 仍在发送 ARP Reply 时，新 MAC 也开始发送
    - 同一 IP 在 5 分钟内出现 2 个以上不同 MAC 且都活跃

  3. 检测方法:
    - 步骤1: 按 SourceProtAddress 分组，统计不同 SourceHwAddress 数量
    - 步骤2: 对每个 SourceHwAddress，检查其在时间窗口内的最后活跃时间
    - 步骤3: 判断是否存在多个 MAC 同时活跃（最后活跃时间差 < 30秒）
    - 步骤4: 如果同时活跃的 MAC 数量 > 1，则判定为冲突
告警级别: 高
```

```yaml
规则名称: ARP_欺骗检测_无请求回复
描述: 检测未收到对应 ARP Request 的 ARP Reply（Gratuitous ARP）
条件:
  - 事件类型: ARP Reply
  - 检查: 过去 10 秒内无对应 ARP Request
  - 匹配条件:
      - DstProtAddress == SourceProtAddress (声称自己是目标)
      - DstHwAddress == "00:00:00:00:00:00" (广播回复)
告警级别: 中

区分正常和可疑的 Gratuitous ARP:
  # 正常 Gratuitous ARP 特征（不告警）
  1. 频率特征:
    - 设备启动时: 通常发送 1-3 次，然后停止
    - IP 地址变更时: 变更后发送 1-2 次
    - 故障恢复时: 恢复后发送少量（< 5 次）
    - 正常频率: < 5 次/小时/设备

  2. IP 特征:
    - 不声称自己是其他设备的 IP（特别是网关 IP）
    - 不与其他已知的 IP-MAC 映射冲突
```

```yaml
规则名称: ARP_欺骗检测_异常回复频率
描述: 检测单个源 MAC 发送异常数量的 ARP 回复
条件:
  - 事件类型: ARP Reply
  - 时间窗口: 1 分钟
  - 聚合字段: SourceHwAddress
  - 统计: COUNT(*)
  - 阈值: > 50
告警级别: 中
```

```yaml
规则名称: ARP_欺骗检测_周期性重复投毒
描述: 检测对同一目标周期性发送的 ARP 回复（保持攻击效果）
条件:
  - 事件类型: ARP Reply
  - 时间窗口: 10 分钟
  - 聚合字段: SourceHwAddress + DstProtAddress
  - 统计: COUNT(*)
  - 阈值: > 10
  - 且: 时间间隔规律（标准差 < 10 秒）
告警级别: 高

说明: 攻击者周期性重复发送 ARP 回复，防止 ARP 缓存过期，保持攻击效果。这是 ARP 表投毒的典型特征。
```

```yaml
规则名称: ARP_欺骗检测_固定目标高频攻击
描述: 检测对特定目标的高频 ARP 回复
条件:
  - 事件类型: ARP Reply
  - 时间窗口: 1 分钟
  - 聚合字段: DstProtAddress
  - 统计: COUNT(*)
  - 阈值: > 10
  - 且: 来自同一 SourceHwAddress
告警级别: 高

说明: 针对特定目标持续发送 ARP 回复，确保 ARP 缓存被持续污染。
```

---

### 2. ARP 中间人攻击（MITM）

#### 特征描述:reply

攻击者同时欺骗网关和受害者，实现双向流量劫持。

#### 流量特征

| 特征项                   | 正常行为 | 攻击行为                | 检测阈值    |
| ------------------------ | -------- | ----------------------- | ----------- |
| **同一 MAC 声称多个 IP** | 无       | 有（网关 IP + 其他 IP） | 出现即告警  |
| **网关 IP 映射变化**     | 稳定     | 频繁变化                | > 2 次/小时 |
| **双向 ARP 异常**        | 无       | 同时欺骗双方            | 出现即告警  |
| **MAC 地址与网关不一致** | 一致     | 不一致                  | 出现即告警  |

#### 检测规则

```yaml
规则名称: ARP_MITM检测_同一MAC多IP
描述: 检测同一 MAC 地址声称拥有多个 IP 地址（特别是网关 IP）
条件:
  - 事件类型: ARP Reply
  - 时间窗口: 10 分钟
  - 聚合字段: SourceHwAddress
  - 统计: COUNT(DISTINCT SourceProtAddress)
  - 阈值: >
  - 特殊检查: 包含网关 IP
告警级别: 高
```

```yaml
规则名称: ARP_MITM检测_网关MAC变化
描述: 检测网关 IP 对应的 MAC 地址异常变化
条件:
  - 事件类型: ARP Reply
  - 匹配: SourceProtAddress == 网关IP
  - 时间窗口: 1 小时
  - 聚合字段: SourceProtAddress
  - 统计: COUNT(DISTINCT SourceHwAddress)
  - 阈值: >
  - 白名单: 排除已知合法 MAC
告警级别: 高
```

```yaml
规则名称: ARP_MITM检测_双向欺骗模式
描述: 检测同时欺骗网关和受害者的双向欺骗模式
条件:
  - 事件类型: ARP Reply
  - 时间窗口: 5 分钟
  - 聚合字段: SourceHwAddress
  - 检测逻辑:
      # 双向欺骗的核心特征
      1. 同一 MAC 声称拥有网关 IP:
         - SourceProtAddress == 网关IP
         - SourceHwAddress == 攻击者MAC
         - DstProtAddress == 受害者IP（向受害者声称自己是网关）

      2. 同一 MAC 声称拥有受害者 IP:
         - SourceProtAddress == 受害者IP
         - SourceHwAddress == 攻击者MAC（同一MAC）
         - DstProtAddress == 网关IP（向网关声称自己是受害者）

      3. 时间窗口内同时出现以上两种情况

  - 统计条件:
      - 步骤1: 按 SourceHwAddress 分组
      - 步骤2: 检查是否存在 SourceProtAddress == 网关IP 的记录
      - 步骤3: 检查是否存在 SourceProtAddress != 网关IP 且 SourceProtAddress != 攻击者自己IP 的记录
      - 步骤4: 检查这些记录的 DstProtAddress 是否包含网关IP和其他IP
      - 步骤5: 如果同时满足：同一MAC声称网关IP + 同一MAC声称其他IP，则判定为双向欺骗

  - 阈值:
      - COUNT(DISTINCT SourceProtAddress) > 1（同一MAC声称多个IP）
      - 且: 包含网关IP
      - 且: 包含非网关IP（受害者IP）
      - 且: COUNT(*) >= 2（至少向两个不同目标发送）



告警级别: 高
```

---

### 3. ARP 洪泛攻击（ARP Flooding）

#### 特征描述:request 和 reply

发送大量伪造或随机的 ARP 请求/回复，耗尽网络资源。

#### 流量特征

| 特征项             | 正常行为 | 攻击行为     | 检测阈值              |
| ------------------ | -------- | ------------ | --------------------- |
| **ARP 包速率**     | < 100/秒 | > 1000/秒    | > 500/秒              |
| **随机 IP 地址**   | 无       | 大量随机 IP  | > 100 个不同 IP/分钟  |
| **随机 MAC 地址**  | 无       | 大量随机 MAC | > 100 个不同 MAC/分钟 |
| **无效 IP 地址**   | 无       | 包含无效 IP  | 出现即告警            |
| **ARP 包大小异常** | 标准大小 | 异常大小     | 偏离标准 > 20%        |

#### 检测规则

```yaml
规则名称: ARP_洪泛检测_高频率请求
描述: 检测异常高频率的 ARP 请求
条件:
  - 事件类型: ARP Request
  - 时间窗口: 1 秒
  - 聚合字段: SourceHwAddress
  - 统计: COUNT(*)
  - 阈值: > 500
告警级别: 高
```

```yaml
规则名称: ARP_洪泛检测_随机IP扫描
描述: 检测来自同一源的大量不同目标 IP 的 ARP 请求
条件:
  - 事件类型: ARP Request
  - 时间窗口: 1 分钟
  - 聚合字段: SourceHwAddress
  - 统计: COUNT(DISTINCT DstProtAddress)
  - 阈值: > 50
告警级别: 中
```

```yaml
规则名称: ARP_洪泛检测_无效地址
描述: 检测包含无效 IP 或 MAC 地址的 ARP 包
条件:
  # ARP Request 检测
  - 事件类型: ARP Request
  - 匹配条件:
      - SourceHwAddress == "00:00:00:00:00:00" (请求者MAC不能是全0)
      - SourceProtAddress 不在有效 IP 范围内
      - DstProtAddress 不在有效 IP 范围内
      - DstHwAddress 格式异常（虽然通常为全0，但格式必须正确）

  # ARP Reply 检测
  - 事件类型: ARP Reply
  - 匹配条件:
      - SourceHwAddress == "00:00:00:00:00:00" (回复者MAC不能是全0)
      - SourceProtAddress 不在有效 IP 范围内
      - DstProtAddress 不在有效 IP 范围内
      - DstHwAddress == "00:00:00:00:00:00" (Reply中目标MAC应该是具体地址，不能是全0，除非是Gratuitous ARP)
      - DstHwAddress 格式异常

告警级别: 高
```

---

### 4. ARP 扫描/探测（ARP Scanning）

#### 特征描述:request

系统性地扫描网段内所有 IP 地址，探测活跃主机。

#### 流量特征

| 特征项           | 正常行为 | 攻击行为       | 检测阈值        |
| ---------------- | -------- | -------------- | --------------- |
| **连续 IP 扫描** | 无       | 有（顺序扫描） | > 10 个连续 IP  |
| **扫描速度**     | 慢       | 快             | > 50 个 IP/分钟 |
| **扫描范围**     | 小       | 大（整个网段） | > 50% 网段      |
| **无业务关联**   | 有       | 无             | 仅 ARP 流量     |

#### 检测规则

```yaml
规则名称: ARP_扫描检测_连续IP探测
描述: 检测对连续 IP 地址的 ARP 请求
条件:
  - 事件类型: ARP Request
  - 时间窗口: 5 分钟
  - 聚合字段: SourceHwAddress
  - 检查: DstProtAddress 是否连续
  - 统计: COUNT(DISTINCT DstProtAddress)
  - 阈值: > 20 且连续度 > 80%
告警级别: 中
```

```yaml
规则名称: ARP_扫描检测_网段扫描
描述: 检测对大量网段内 IP 的 ARP 请求
条件:
  - 事件类型: ARP Request
  - 时间窗口: 10 分钟
  - 聚合字段: SourceHwAddress
  - 统计: COUNT(DISTINCT DstProtAddress)
  - 阈值: > 100
  - 且: 扫描范围 > 网段的 30%
告警级别: 中
```

```yaml
规则名称: ARP_扫描检测_快速扫描
描述: 检测短时间内大量 ARP 请求
条件:
  - 事件类型: ARP Request
  - 时间窗口: 1 分钟
  - 聚合字段: SourceHwAddress
  - 统计: COUNT(*)
  - 阈值: > 200
告警级别: 中
```

---

## 三、综合检测指标

### 基础统计指标

```yaml
指标名称: ARP_流量基线
描述: 建立正常 ARP 流量基线
统计项:
  - ARP Request 速率（正常: < 10/秒）
  - ARP Reply 速率（正常: < 5/秒）
  - 唯一 IP 数量（正常: < 50/分钟）
  - 唯一 MAC 数量（正常: < 50/分钟）
  - IP-MAC 映射变化频率（正常: < 1/小时）
```

### 异常行为指标

```yaml
指标名称: ARP_异常行为评分
描述: 综合评分系统
评分项:
  - IP-MAC 冲突: +10 分
  - 无请求回复: +8 分
  - 高频率请求: +5 分
  - 扫描行为: +5 分
  - 网关 MAC 变化: +10 分
  - 同一 MAC 多 IP: +8 分
阈值: 总分 > 15 分触发告警
```

---

## 四、关联分析规则

### 规则 1: ARP 异常 + 流量异常

```yaml
规则名称: ARP_关联检测_流量劫持
描述: ARP 异常后检测流量模式变化
条件:
  - 步骤1: 检测到 ARP 欺骗
  - 步骤2: 检测到异常流量模式
    - 同一源 MAC 的流量增加
    - 目标设备流量减少
    - 出现异常协议流量
告警级别: 高
```

### 规则 2: ARP 扫描 + 后续攻击

```yaml
规则名称: ARP_关联检测_扫描后攻击
描述: 检测扫描行为后的攻击活动
条件:
  - 步骤1: 检测到 ARP 扫描（时间窗口: 1 小时）
  - 步骤2: 检测到针对扫描目标的攻击
    - ARP 欺骗
    - 端口扫描
    - 异常连接
告警级别: 高
```

---

## 五、检测规则配置建议

### 时间窗口设置

- **实时检测**: 1-5 秒（高优先级告警）
- **短期检测**: 1-5 分钟（扫描、洪泛）
- **中期检测**: 10-60 分钟（MITM、投毒）
- **长期检测**: 1-24 小时（基线异常）

### 阈值调优建议

1. **初始设置**: 使用建议阈值
2. **基线学习**: 观察 1-2 周，建立正常基线
3. **动态调整**: 根据误报率调整阈值
4. **白名单**: 排除已知合法设备（如网络管理工具）

### 告警级别定义

- **高**: 立即响应（ARP 欺骗、MITM）
- **中**: 调查分析（扫描、洪泛）
- **低**: 记录观察（异常但可能合法）

---

## 六、SIEM 查询示例

### Elasticsearch/Splunk 查询示例

#### 查询 1: IP-MAC 冲突检测（区分正常切换和攻击冲突）

**方法 1: 简单检测（可能误报正常切换）**

```
index=network protocol=ARP operation=Reply
| stats dc(SourceHwAddress) as mac_count,
        values(SourceHwAddress) as mac_list by SourceProtAddress
| where mac_count > 1
| sort -mac_count
```

**方法 2: 精确检测（区分正常切换和冲突）**

```
index=network protocol=ARP operation=Reply
| bucket _time span=5m
| stats
    dc(SourceHwAddress) as mac_count,
    values(SourceHwAddress) as mac_list,
    max(_time) as last_seen,
    min(_time) as first_seen,
    latest(SourceHwAddress) as latest_mac,
    earliest(SourceHwAddress) as earliest_mac
    by SourceProtAddress, _time
| where mac_count > 1
| eval time_span = last_seen - first_seen
| eval is_conflict = if(time_span < 30 AND mac_count > 1, "冲突", "可能正常切换")
| where is_conflict = "冲突"
| sort -mac_count
```

**方法 3: 基于活跃时间的冲突检测（推荐）**

```
index=network protocol=ARP operation=Reply
| bucket _time span=1m
| stats
    dc(SourceHwAddress) as mac_count,
    values(SourceHwAddress) as mac_list,
    max(_time) as last_seen_mac1,
    min(_time) as first_seen_mac1
    by SourceProtAddress, SourceHwAddress
| stats
    dc(SourceHwAddress) as total_mac_count,
    values(SourceHwAddress) as all_macs,
    max(last_seen_mac1) as latest_activity,
    min(first_seen_mac1) as earliest_activity
    by SourceProtAddress
| where total_mac_count > 1
| eval overlap_time = latest_activity - earliest_activity
| eval is_conflict = if(overlap_time < 30 AND total_mac_count > 1, "冲突", "正常切换")
| where is_conflict = "冲突"
| sort -total_mac_count
```

#### 查询 2: 无请求的 ARP 回复

```
index=network protocol=ARP operation=Reply
| join type=left SourceProtAddress, DstProtAddress [
    search index=network protocol=ARP operation=Request
    | stats count by SourceProtAddress, DstProtAddress
]
| where isnull(count)
```

#### 查询 3: 高频率 ARP 请求

```
index=network protocol=ARP operation=Request
| bucket _time span=1m
| stats count by SourceHwAddress, _time
| where count > 100
```

---

## 八、参考指标

### 正常网络 ARP 流量特征

- ARP Request: 1-10 个/分钟/设备
- ARP Reply: 0.5-5 个/分钟/设备
- IP-MAC 映射变化: < 1 次/小时
- 唯一 IP 扫描: < 10 个/小时/设备

### 攻击流量特征对比

| 攻击类型 | 请求速率 | 回复速率 | IP 数量  | MAC 数量 |
| -------- | -------- | -------- | -------- | -------- |
| 正常     | < 10/分  | < 5/分   | < 50/时  | < 50/时  |
| 扫描     | > 50/分  | 正常     | > 100/时 | 1        |
| 欺骗     | 正常     | > 10/分  | 1-5      | 1        |
| 洪泛     | > 500/分 | > 500/分 | > 100/分 | > 100/分 |
