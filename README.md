# PathWeaver SD-WAN

PathWeaver 是一个自托管的全节点面板 SD-WAN。所有设备安装同一套节点软件并提供完整管理面板，数据面由 WireGuard 承载；用户不再选择“中心”或“边缘”角色。

## 初始节点一键安装

适用于带 `systemd` 的 x86_64 或 arm64 Linux。在第一台设备直接执行：

```bash
curl -fsSL "https://raw.githubusercontent.com/FengYuchen1314/sd-wan/main/scripts/install.sh?cache=$(date +%s)" | sudo bash -s -- --source https://raw.githubusercontent.com/FengYuchen1314/sd-wan/main
```

安装器会自动补齐基础工具；如果系统没有 Node.js，或版本低于 `22.5`，会下载、校验并安装 PathWeaver 私有的 Node.js 22 运行时，不会替换系统已有 Node.js。随后安装器会自动识别这是初始节点，依次检测管理面板 TCP `19773` 和 WireGuard UDP `19801`；直接回车使用检测到的空闲端口，并按提示输入两次本机面板密码。完成后访问 `http://<这台设备的 IP>:19773`。后续设备请从面板“接入新节点”生成一次性命令，不要重复使用上面的初始节点命令。

> 推送到 GitHub `main` 分支后上述命令才可下载本仓库。公网部署应使用 HTTPS 反向代理，并只向可信管理网开放面板；通过纯 HTTP 传递安装包不具备抗中间人篡改能力。

## 已安装节点原地更新

仓库推送到 GitHub `main` 分支后，在需要更新的节点执行本机命令：

```bash
sudo pathweaver-update
```

更新器不依赖在线下载安装脚本：它先尝试 GitHub；GitHub 不可达时，会读取本机保存的初始上游、已验证控制邻接以及中心数据库中的可中继节点，逐个探测并从第一台能提供完整制品的节点拉取。也可用 `sudo pathweaver-update --source http://节点IP:控制端口` 指定首选来源。更新模式不会再次询问端口或密码，也不会重新初始化节点。它会替换 `/opt/pathweaver/current` 指向的程序版本、修补或补齐 PathWeaver 私有 WireGuard 运行时并重启已有服务，保留数据库、节点密钥、面板端口、WireGuard 端口与当前网络配置；如果新版服务不能保持运行，会自动恢复到更新前的程序版本。父节点更新完成后，其 `/install.sh` 和安装包接口会自动向后续节点分发新版。

从不含 `pathweaver-update` 的旧版本首次升级时，需要先执行一次原有 GitHub 更新命令；若该设备无法访问 GitHub，也可把一台已经更新的可达节点作为来源：`curl -fsSL 'http://节点IP:控制端口/install.sh' | sudo bash -s -- --source 'http://节点IP:控制端口' --update`。完成这一次迁移后，后续只需运行本机的 `sudo pathweaver-update`。

## 本机离线卸载

安装完成后，卸载器已经保存在本机，不需要访问 GitHub、面板或其他节点。卸载节点前，建议先在面板删除该节点；如果它是当前配置协调节点，应先等待或完成协调权迁移。

移除 systemd 服务、程序、私有 WireGuard 运行时和运行中的网络接口，同时保留本机数据库与节点密钥以便恢复：

```bash
sudo pathweaver-uninstall
```

确认不再需要恢复时，可永久删除本机数据库、节点身份、密钥和缓存：

```bash
sudo pathweaver-uninstall --purge
```

`--purge` 不可撤销。两个命令都只使用安装时写入 `/usr/local/sbin/pathweaver-uninstall` 的本地脚本，不下载或执行任何云端内容。

当前仓库包含第一阶段可运行骨架：

- 每个节点都提供中文管理面板，默认 TCP `19773`
- 安装时交互设置本机面板密码，使用带随机盐的 scrypt 摘要保存
- 面板读写通过当前无环控制路径实时转发，所有节点看到同一份版本化配置
- SQLite WAL 串行写入、逻辑快照多数派复制和配置协调权自动迁移
- 节点组、节点 IP、上下游拓扑管理
- 随连接关系自动收敛的拓扑画布，支持 Ctrl + 滚轮缩放、画布平移和节点拖动固定
- 双节点路径详情、无环多路径枚举、Linux ECMP 加权分流与 20 秒健康成员摘除/恢复
- 画布式节点选择、单边或双边可达地址填写和按方向连接验证
- 单向 NAT 链路在配置激活后由持有 Endpoint 的一端立即发起数据面预热，建立出口映射
- 普通拓扑链路握手故障时自动绕开，保留无路由健康 Peer 继续复检，恢复后重新启用
- 全网可达性与地址冲突校验
- 基于拓扑的逐节点 WireGuard 配置编译
- 一次性加入令牌与安装命令生成
- 统一对等节点安装脚本；无需选择角色，本机自动探测面板、控制中继和 WireGuard 端口
- 私有业务网段预览、全节点本机路由冲突预检和两阶段提交
- Agent 注册、心跳、配置准备/激活和命令轮询
- 两端 Agent 准备、仅对已填写方向发起互访探测，任一方向成功后自动激活新通路
- 节点级 WireGuard 端口持久化；默认从 UDP 19801 自动寻找空闲端口，也可在安装或面板中指定
- 探测 ID、访问轨迹、跳数上限、超时与中继环路保护
- 固定版本、校验哈希的 PathWeaver 私有 WireGuard 工具运行时；每次部署均独立安装，不调用宿主机已有 `wg`
- Linux WireGuard 配置渲染与安全应用

加权策略会为每条活动路径分配独立的端点别名和 IPIP 隧道，再把受该策略接管的目的网段写成 Linux 按连接哈希的加权 ECMP 路由；故障成员会从下一配置版本移除，20 秒复检恢复后按原权重加入。配置写入在返回成功前同步到当前选民多数派；协调节点失联且租约到期后，持有最新快照的节点通过多数派选举自动接管，旧协调节点恢复后会降级并同步新快照。安全自动迁移需要至少 3 个可互通的普通节点；单节点可独立工作，双节点在任一节点失联时会拒绝写入而不会冒险形成双主。发布生产网络前仍应在测试节点验证内核 IPIP/ECMP、端口、防火墙和回滚流程。

## 本地运行

需要 Node.js 22.5 或更高版本（使用内置 SQLite）。

```bash
npm start
```

开发环境兼容密码 `dev-admin-token`，访问 `http://127.0.0.1:19773`。

生产环境必须显式设置：

```bash
SDWAN_PANEL_PASSWORD_HASH='scrypt-v1$...' \
SDWAN_PUBLIC_URL='https://sdwan.example.com' \
SDWAN_DATA_DIR='/var/lib/pathweaver' \
npm start
```

## 测试

```bash
npm test
```

详细设计见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。
