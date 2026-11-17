# CARD-005 安全加固说明

适用源码基线：`3d5c9b832285cbfcbb24d946312826880589c456`（与 chu0119/Pojun v0.4.80 同一提交、同一棵树）。
其他提交、脏工作树和其他版本不在本说明的测试范围内。

本文件只描述源码变化。应用补丁不会重启服务，不会改已有管理员密码，也不会改数据库口令。
构建和重启由操作员在核对差异后自行进行。

## 操作员必须知道的行为变化

- 新实例的 `POST /api/auth/init` 需要一次性初始化口令。进程在发现尚未设置管理员密码时把它打印到日志。`POJUN_INIT_TOKEN` 若已设置则使用该值且不打印。已经有密码的实例仍然拒绝 init，密码哈希不变。
- 同用户可以阅读这份日志。这只挡住未持有口令的网络访问者。
- 主程序默认监听 `127.0.0.1:8787`。容器内进程仍监听容器的 `:8787`，compose 只把宿主的 `127.0.0.1:8787` 映射进去。要对外监听必须显式修改地址。
- 浏览器会话使用 HttpOnly、SameSite=Strict 的 cookie，有效期 24 小时。页面不再把 JWT 写入 localStorage。登录 JSON 仍返回 token，供非浏览器客户端使用。
- 默认不信任 `X-Forwarded-For` / `X-Real-IP`。反代之后要设置 `POJUN_TRUSTED_PROXIES`。
- 登录失败不再因为全局计数锁死所有地址。
- hostd 服务模式必须带 `-allow-exe`。它核验对端可执行文件路径，不使用同 UID 可读的共享 token。直接执行该 pojun 二进制，或在内核允许 ptrace 时附着主进程，仍然可能驱动 hostd。
- hostd 忽略请求体里的 proxy，只用自己进程环境里的 `POJUN_INSTALL_PROXY`（或 `HTTPS_PROXY` / `HTTP_PROXY`）。自我换装拒绝降级到更低的三段版本号。
- GitHub / pip / script 安装配方默认拒绝，除非 hostd 进程有 `POJUN_HOSTD_ALLOW_UNVERIFIED=1`。该开关不提供摘要校验。
- 容器默认不再在启动时预装工具。Docker 构建不再执行未提供摘要的 NodeSource 脚本，也不再拉取未钉版本的 nuclei 或 `@latest` Playwright。
- `.env.example` 不再包含可用的数据库口令或 `latest` 标签。已有 `.env` 不会被改写。
- 已在本仓库解析并升级、且 `go build ./...` 通过的 Go 依赖：`golang.org/x/net v0.62.0`、`golang.org/x/crypto v0.58.0`（`x/net v0.62.0` 要求至少 v0.58.0）、`github.com/klauspost/compress v1.20.2`、`github.com/andybalholm/brotli v1.2.7`。
- 前端锁文件已升到 `next@16.4.6`、`postcss@8.5.23`、`zod@4.6.7`。`npx tsc --noEmit` 与 `NEXT_EXPORT=1 npx next build` 在本环境通过。之后 `npm audit` 仍报告 21 项（critical 1、high 12、moderate 8），没有执行 `npm audit fix`，也不把这说成前端依赖已清空。
- Python FOFA 锁文件没有升级：本环境没有完成可验证的解析。这不是完整依赖审计。
