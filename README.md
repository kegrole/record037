# tlsaudit

纯 Python 标准库实现的 OpenSSL 风格 TLS 配置审计器，零第三方依赖。

## 运行

```
python -m tlsaudit.cli --dir demo/openssl_cfgs --out out/report.json
```

扫描目录下所有配置文件，把 JSON 报告写入 `--out`，并在 stdout 打印一行摘要
（配置数、问题总数、各问题类型分布）。`python -m tlsaudit` 等价。

## 配置格式

每行一条 `key = value` 指令；`#` 与 `;` 开头为注释，`[section]` 头被忽略：

```
TLSv1.2 = server            # 启用协议（server/client/on/yes/true/1）
SSLv3 = off                 # 显式禁用（none/off/no/false/0）
CipherString = DEFAULT:!aNULL:+RC4-SHA
Ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
```

- 协议键：`SSLv2`、`SSLv3`、`TLSv1`、`TLSv1.1`、`TLSv1.2`、`TLSv1.3`（大小写不敏感）。
- 文件完全没有协议指令时，默认启用 TLSv1.2 与 TLSv1.3。
- `CipherString` 控制 TLS 1.2 及以下套件；`Ciphersuites` 单独列出 TLS 1.3 套件。
- 未识别的指令直接忽略（与 OpenSSL 行为一致）。

## CipherString 增删语义

token 之间用 `:` 或 `,` 分隔（空白也可），按顺序处理：

- `DEFAULT`：把当前列表重置为内建基线（剔除弱/NULL/EXPORT/MD5 套件后的全集）。
- 裸 token：匹配到的套件追加进列表（已存在则跳过）。
- `+TOKEN`：把匹配套件移动/追加到列表末尾。
- `-TOKEN`：从列表移除匹配套件，之后仍可被重新加入。
- `!TOKEN`：永久排除匹配套件，之后任何操作都无法再加回。
- `@SECLEVEL=n`：记录安全级别，写入报告的 `seclevel` 字段（未写时为 `null`）。
- `@STRENGTH`：最终列表按加密强度降序排序。

token 可以是完整套件名（如 `ECDHE-RSA-AES128-GCM-SHA256`），也可以是别名
（`aNULL`、`eNULL`、`RC4`、`3DES`、`DES`、`EXPORT`、`AESGCM`、`ECDHE`、`DHE`、`SHA256` 等），
别名按套件元数据匹配，不是字符串前缀匹配。

## 判定口径

- **协议**：启用 `SSLv2`/`SSLv3`/`TLSv1`/`TLSv1.1` 即报 `deprecated_protocol`
  （SSLv2/SSLv3 为 critical，TLSv1/1.1 为 high）；TLSv1.2 与 TLSv1.3 正常。
- **弱套件**：对启用集合逐个检查，RC4、DES、3DES、RC2、EXPORT、NULL 加密、
  匿名认证（aNULL）各自产生一条 `weak_cipher` 问题，evidence 中点名具体套件。
- **前向保密**：启用集合中不存在任何 ECDHE 或 DHE 密钥交换的套件时，报一条
  `no_forward_secrecy`，evidence 列出全部启用套件名。
- **AEAD**：启用集合中存在加密算法带 `GCM`、`CHACHA20` 或 `CCM` 的套件时，
  报告 `aead_available` 为 `true`。
- **安全级别**：`@SECLEVEL=0` 额外产生一条 `insecure_seclevel` 问题。

## 报告格式

```json
{
  "summary": {"config_count": 6, "issue_count": 12, "issue_types": {"weak_cipher": 4}},
  "configs": [
    {
      "file": "demo/openssl_cfgs/modern.cnf",
      "enabled_protocols": ["TLSv1.2", "TLSv1.3"],
      "enabled_ciphers": ["ECDHE-RSA-AES128-GCM-SHA256", "..."],
      "aead_available": true,
      "seclevel": null,
      "issues": [{"name": "...", "evidence": "...", "severity": "..."}]
    }
  ]
}
```

## 测试

```
cd tests && python -m unittest test_tlsaudit -v
# 或在仓库根目录：python -m unittest discover -s tests -v
```

测试在临时目录里重新生成全部夹具配置，覆盖七条验收口径与增删语义边界
（`!` 永久排除、`-` 可恢复、逗号/冒号等价、`@STRENGTH` 排序）。

