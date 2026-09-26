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
- `POST /api/packages`：为查阅请求创建交付包草稿（同一案件同一时间只有一个未完成包）
- `POST /api/packages/items`、`POST /api/packages/items/update`、`POST /api/packages/items/remove`：逐项登记系统、类别、遮蔽状态和内容指纹（可传 `content` 自动算 SHA-256，或传 64 位十六进制 `content_fingerprint`）
- `POST /api/packages/seal`：封包。仍有法律保留、第三方遮蔽未完成或已分类位置未全部纳入时拒绝；成功后清单与指纹冻结并生成 `seal_hash`
- `POST /api/packages/release`：发出已封包的交付包
- `POST /api/packages/correct`：对已封包/已发出的包补正，生成带原因的新版本草稿并复制条目，旧版本保留可查
- `POST /api/packages/withdraw`：撤回未发出的包，释放待处理位置并记录时间线
- `GET /api/packages/{id}`：查看任意版本及条目；`GET /api/requests/{id}` 返回 `packages` 和 `package_summary`（`sealable` 可封包、`pending_correction` 待补正、`released` 已发出、`history` 已取代/已撤回）

## 交付包生命周期

`draft → sealed → released`，补正使旧版本变为 `superseded`（已发出的保留 `released` 并标记 `superseded_by`），未发出可撤回为 `withdrawn`。封包时位置变为 `packaged`，发出后变为 `delivered`，撤回或补正已封包时释放回 `classified`。草稿包在案件详情中附带 `seal_ready` 和 `seal_blockers`，说明能否封包及阻塞原因。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试覆盖完整查阅请求、第三方遮蔽、未成年人/代理限制、重复与幂等、延期上限、删除法律保留、权限拒绝和版本冲突，以及交付包的封包门禁（法律保留/第三方遮蔽/位置完整性）、封包冻结、发出、撤回释放位置、补正版本链和历史版本可查。

## 局限

身份依赖请求头，联系方式只存哈希；请求正文、证据文件和实际回复文件未实现加密存储；地区规则是可配置模板，不构成法律意见；删除是流程判定，不会自动调用外部业务系统执行清除。
