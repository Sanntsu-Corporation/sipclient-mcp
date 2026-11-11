# 在 Codex、Claude Code 與 Claude Desktop 中加入 sipclient-mcp

本文件的目的，是帶著你（開發者）把 `sipclient-mcp` 這個 MCP 伺服器與
它的輔助 skill 安裝起來，讓你的程式碼 agent（Codex、Claude Code，或是
Claude Desktop 桌面應用程式）能夠使用它們。

## 背景與功能

`sipclient-mcp` 是一個可透過網路連線存取的開發用 daemon，透過 MCP
（Model Context Protocol）對外提供一套真正可用的 SIP UAC/UAS 協定堆疊：
建立使用者代理
（UA）、撥打／接聽／掛斷通話、轉接已接通的通話（盲轉或諮詢轉接）、收發
DTMF、播放／錄製媒體、擷取每通電話的 pcap 封包，以及讀取語音品質指標——
這些全部都以工具呼叫的形式（`ua_create`、`call_dial`、`call_transfer`、
`dtmf_send`、`media_*`、`capture_*`、`quality_get` 等）直接讓 AI 程式碼代理
（agent）驅動。它存在的目的，是讓正在開發這個 repo（或任何與 SIP 相關的
程式碼庫）的 agent，能夠在開發過程中端到端地實際跑一次通話流程，而不需要
人類手動撥打測試電話。

要真正用起來，需要兩個各自獨立的部分：

- **MCP 伺服器**提供工具本身——這是你的 agent 要「連線」的對象。
- **`sipclient-mcp` skill**（目前為 BETA 版）則是一份輔助文件，教會
  agent *如何正確使用*這些工具：session／UA／call 的觀念、典型的通話／
  轉接流程，以及已知的注意事項。伺服器給 agent 能力，skill 給 agent 正確
  使用這份能力的知識。就算不裝 skill，工具依然能呼叫，但 agent 比較容易
  用錯（例如把 session 和 UA 搞混）。

這個 daemon 支援**多組各自獨立的 bearer token**——可以每台機器、每個
agent 各發一組，之後要撤銷某一組時也不會影響到其他人；預設只監聽
loopback；維運者可用 `--listen` 改成其他位址（請先閱讀 README 的 Security model）。以下範例使用 8100 埠，
並假設可透過**`<DAEMON_HOST>:8100`**（執行 daemon
那台機器的位址，請向維運者確認）連線，或是透過 VPN 連線。你需要向 daemon 的維運者索取屬於你
自己的 token；請勿沿用別人的 token，也絕對不要把另外那組專用的
*admin* token 拿來做一般工具存取（admin token 只給
`config_get`／`config_set`／`admin_token_rotate` 這幾個管理專用工具用）。

## 事前準備

- 一組由 daemon 維運者發給你的 bearer token。
- 能連到 `<DAEMON_HOST>:8100`（直接連線或透過 VPN）。如果你剛好就在
  daemon 所在的那台主機上，`127.0.0.1:8100` 也可以用。

## 加入 MCP 伺服器

### Codex CLI

Codex 是從環境變數讀取 bearer token，而不是直接存進 `config.toml`，所以
先設定環境變數：

```bash
export SIPCLIENT_MCP_TOKEN="<your-token>"
codex mcp add sipclient-mcp \
  --url http://<DAEMON_HOST>:8100/mcp \
  --bearer-token-env-var SIPCLIENT_MCP_TOKEN
```

驗證：

```bash
codex mcp list
codex mcp get sipclient-mcp
```

### Claude Code

```bash
claude mcp add --transport http sipclient-mcp \
  http://<DAEMON_HOST>:8100/mcp \
  --header "Authorization: Bearer <your-token>" \
  -s user
```

`-s user` 會把它註冊成這台機器上每個專案都能用（跟 daemon 主機自己目前
的註冊方式一致）；如果你只想在某一個特定的 repo 內使用，改用
`-s project` 即可。

驗證：

```bash
claude mcp list
```

應該會看到 `sipclient-mcp` 顯示為 `Connected`。

備註：跟 Codex 不同，這個指令是把 token 直接寫在指令列上，而不是透過
環境變數間接帶入——如果你在意這台機器上的 shell 歷史紀錄，請留意別讓
token 留在裡面。

### Claude Desktop 桌面應用程式

請不要用「設定 → 連接器（Connectors）」裡的「自訂連接器」來加這個伺服
器。這條路徑不管在哪個 Claude 介面上（包含 Desktop），一律會透過
Anthropic 的雲端基礎設施轉接連線——所以用這種方式加入的伺服器，必須能從
公開網際網路連到才行，而這個 daemon 刻意只開放給私有網路／VPN，不是設計
成這樣用的。

正確做法是改用 Desktop 的**本機（stdio）MCP 設定**，透過
[`mcp-remote`](https://github.com/punkpeye/mcp-remote) 這個小工具來橋接：
它是 Desktop 在*你自己這台機器上*啟動的一個小程式，由它自己去對
`<DAEMON_HOST>:8100` 發出 HTTP 請求——跟你在本機執行 `curl` 是一樣的道
理，完全不需要對外開放。這需要你的桌機上有安裝 Node.js（才有 `npx`
可用）。

請編輯 `claude_desktop_config.json`：

- macOS：`~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows：`%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "sipclient-mcp": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://<DAEMON_HOST>:8100/mcp",
        "--header",
        "Authorization:${AUTH_TOKEN}"
      ],
      "env": {
        "AUTH_TOKEN": "Bearer <your-token>"
      }
    }
  }
}
```

改完後請完全結束再重新開啟 Claude Desktop，設定才會生效。

## 加入 skill

skill 檔案本身放在這個 repo 裡的
`.claude/skills/sipclient-mcp/SKILL.md`。

### Codex CLI

Codex 會從 `$CODEX_HOME/skills/<name>/SKILL.md`（預設是
`~/.codex/skills`）載入 skill：

```bash
# from the repository root
mkdir -p ~/.codex/skills/sipclient-mcp
cp .claude/skills/sipclient-mcp/SKILL.md \
   ~/.codex/skills/sipclient-mcp/SKILL.md
```

如果你是在別台機器上操作，請改從這個 repo 的 `main` 分支把同一份檔案
抓下來，而不是直接複製這個本機路徑。

### Claude Code

這個 repo 裡已經有追蹤 `.claude/skills/sipclient-mcp/SKILL.md`
（專案層級的 skill），所以只要 Claude Code 是在這個 repo 的工作目錄底下
執行，就會自動載入——不需要再做任何事。

如果想讓這台機器上*每個*專案都能用，而不只是這個 repo，可以改複製到
使用者層級的 skills 目錄：

```bash
# from the repository root
mkdir -p ~/.claude/skills/sipclient-mcp
cp .claude/skills/sipclient-mcp/SKILL.md \
   ~/.claude/skills/sipclient-mcp/SKILL.md
```

### Claude Desktop 桌面應用程式

Desktop 並沒有另外一套可以安裝 skill 的機制——它是直接靠 MCP 伺服器自己
回傳的工具說明在運作。這樣就足夠做基本操作了；如果想了解 skill 裡教的
session／UA／call 觀念與已知的注意事項，可以直接去讀這個 repo 裡的
`.claude/skills/sipclient-mcp/SKILL.md`。

## 驗證是否成功

請你的 agent 執行一個唯讀的工具呼叫，例如「列出我的 sipclient-mcp
通話」——它應該會呼叫 `call_list`，然後拿到類似
`{"ok":true,"calls":[]}` 的結果。如果出現 401，代表 token 錯誤或沒帶；
如果是連線錯誤，代表你這端連不到 daemon——這兩種情況都請回報給維運者，
不要自己亂猜著修。
