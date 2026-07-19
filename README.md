# PathWeaver SD-WAN

PathWeaver 是一个自托管的 SD-WAN 控制器与边缘 Agent。中心服务器提供管理面板、节点注册、拓扑编排和配置下发；数据面由 WireGuard 承载。

当前仓库包含第一阶段可运行骨架：

- 中心控制服务和中文管理面板
- SQLite 持久化
- 节点组、节点 IP、上下游拓扑管理
- 随连接关系自动收敛的拓扑画布，支持 Ctrl + 滚轮缩放、画布平移和节点拖动固定
- 双节点路径详情、无环多路径枚举、加权负载均衡策略、20 秒故障摘除/恢复和版本化下发
- 画布式节点选择、双向可达地址填写和连接验证
- 全网可达性与地址冲突校验
- 基于拓扑的逐节点 WireGuard 配置编译
- 一次性加入令牌与安装命令生成
- 统一交互式中心/边缘安装脚本；本机自动探测 TCP 控制端口和 UDP WireGuard 端口
- 私有业务网段预览、全节点本机路由冲突预检和两阶段提交
- Agent 注册、心跳、配置准备/激活和命令轮询
- 两端 Agent 准备、互访探测、验证成功后自动激活新通路
- 节点级 WireGuard 端口持久化；默认从 UDP 19801 自动寻找空闲端口，也可在安装或面板中指定
- 探测 ID、访问轨迹、跳数上限、超时与中继环路保护
- 固定版本、校验哈希的 PathWeaver 私有 WireGuard 工具运行时；每次部署均独立安装，不调用宿主机已有 `wg`
- Linux WireGuard 配置渲染与安全应用

## 本地运行

需要 Node.js 22.5 或更高版本（使用内置 SQLite）。

```bash
npm start
```

开发环境默认管理令牌为 `dev-admin-token`，访问 `http://127.0.0.1:8787`。

生产环境必须显式设置：

```bash
SDWAN_ADMIN_TOKEN='replace-with-a-long-random-value' \
SDWAN_PUBLIC_URL='https://sdwan.example.com' \
SDWAN_DATA_DIR='/var/lib/pathweaver' \
npm start
```

## 测试

```bash
npm test
```

详细设计见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。
