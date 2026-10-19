# Acost 客户端

给 Grok 云电脑用的三个文件。仓库里没有账本、小票、备份或凭据。

- `ledgerctl.py`
- `client_config.py`
- `AGENT_USAGE.md`

更新时只覆盖 `/workspace/qiao-ledger-cloud/` 里的这三个同名文件。已有的 `grok.json` 留在原地，不要覆盖，也不要写进这个仓库。不要启动 `server.py`，不要改用 localhost。

覆盖后运行：

```sh
python3 ledgerctl.py meta
```

确认角色和 revision。不要输出 token。
