# 个人数据权利请求处理系统

标准库实现的跨地区数据访问、更正、删除、撤回同意和限制处理请求后台，使用 SQLite 保存案件、数据位置、时限和审计时间线。

## 运行

要求 Python 3.11+（当前 Python 3.9 环境亦可）。

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8210`，数据库默认 `privacy_requests.db`。可用 `--db`、`--host`、`--port` 修改。

## 主要接口

使用 `X-User`、`X-Role` 请求头。角色有 `intake`、`privacy_officer`、`supervisor`、`auditor`。

- `GET /health`、`GET /api/state`、`GET /api/queue`、`GET /api/requests/{id}`
- `POST /api/jurisdictions`：配置处理时限、延期上限、未成年人和代理规则
- `POST /api/subjects`：保存不含明文联系方式的索引
- `POST /api/requests`：创建权利请求，支持幂等键和30天重复请求识别
- `POST /api/requests/verify`、`POST /api/requests/assign`
- `POST /api/locations`、`POST /api/locations/classify`：多系统定位和第三方/保留分类
- `POST /api/requests/extend`、`POST /api/requests/prepare`
- `POST /api/requests/fulfill`、`POST /api/requests/reject`
- `POST /api/locations/fingerprint`：为已分类位置登记内容指纹（64位 SHA-256）和遮蔽状态（`not_required`/`redacted`/`exempted`）
- `POST /api/packages/seal`：按案件汇总已分类位置生成交付包，逐项快照系统、类别、遮蔽状态和内容指纹并计算清单哈希；存在未分类位置、未完成第三方遮蔽或法律保留时不能封包；封包后清单和指纹固定
- `POST /api/packages/release`、`POST /api/packages/withdraw`：发出或撤回交付包；只能撤回未发出的包，撤回会释放待处理位置并记录时间线
- `POST /api/packages/correct`：补正最新交付包，生成带原因的新版本，旧版本保留可查
- `POST /api/requests/reopen`：重开已办结案件
- `GET /api/requests/{id}/packages`：交付包看板，列出可封包位置、待补正版本和已发出版本

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试覆盖完整查阅请求、第三方遮蔽、未成年人/代理限制、重复与幂等、延期上限、删除法律保留、权限拒绝和版本冲突，以及交付包封存校验、撤回释放、补正版本、重开看板和指纹权限。

## 局限

身份依赖请求头，联系方式只存哈希；请求正文、证据文件和实际回复文件未实现加密存储；地区规则是可配置模板，不构成法律意见；删除是流程判定，不会自动调用外部业务系统执行清除。
