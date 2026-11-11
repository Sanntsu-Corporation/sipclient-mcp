# Codex / Claude Code / Claude Desktop に sipclient-mcp を追加する

このドキュメントは、開発者であるあなたが `sipclient-mcp` の MCP サーバー
とその補助 skill をインストールし、あなたのコーディングエージェント
（Codex、Claude Code、または Claude Desktop アプリ）が使えるようにする
ための手順書です。

## 背景と目的

`sipclient-mcp` はネットワーク経由で到達できる開発用デーモンで、
MCP（Model Context Protocol）を通じて実際に動く SIP UAC/UAS スタックを
公開します。ユーザー
エージェント（UA）の作成、発信／応答／切断、通話の転送（ブラインド転送・
コンサルト転送）、DTMF の送受信、メディアの再生／録音、通話ごとの pcap
キャプチャ、音声品質メトリクスの取得——これらすべてがツール呼び出し
（`ua_create`、`call_dial`、`call_transfer`、`dtmf_send`、`media_*`、
`capture_*`、`quality_get` など）として、AI コーディングエージェントから
直接操作できます。人手でテスト用の電話をかける代わりに、このリポジトリ
（あるいは SIP 関連の任意のコードベース）に取り組むエージェントが、開発
中に実際の通話フローをエンドツーエンドで検証できるようにするための
仕組みです。

これを使えるようにするには、独立した 2 つの要素が必要です。

- **MCP サーバー**がツールそのものを提供します——エージェントが
  *接続する*対象です。
- **`sipclient-mcp` skill**（現在 BETA 版）は、それらのツールを
  *正しく使う方法*をエージェントに教える補助ドキュメントです。session／
  UA／call の概念、典型的な通話・転送フロー、既知の注意点などが含まれ
  ます。サーバーはエージェントに能力を与え、skill はその能力を正しく
  使うための知識を与えます。skill がなくてもツール自体は呼び出せます
  が、エージェントが誤用しやすくなります（例：session と UA を混同する
  など）。

このデーモンは**複数の独立した bearer トークン**をサポートしています。
マシンやエージェントごとに 1 つずつ発行し、他に影響を与えずに個別に
無効化できます。既定ではループバックのみで待ち受けます。運用担当者は `--listen` で
別のアドレスを指定できます（その前に README の Security model を参照）。以下の例ではポート 8100 を使い、
**`<DAEMON_HOST>:8100`**（デーモンを動かしているマシンのアドレス。
運用担当者に確認してください）または VPN 経由で到達できるものとします。利用にはデーモンの運用担当者から自分専用の
トークンを受け取ってください。他人のトークンを流用しないこと、また
通常のツールアクセスに別枠の *admin* トークンを使わないこと（admin
トークンは `config_get`／`config_set`／`admin_token_rotate` という
管理専用ツールのためだけに存在します）。

## 事前準備

- デーモンの運用担当者から発行してもらった bearer トークン。
- `<DAEMON_HOST>:8100` への到達性（直接または VPN 経由）。もし
  デーモンが動いているホスト自身で作業している場合は、`127.0.0.1:8100`
  でも接続できます。

## MCP サーバーの追加

### Codex CLI

Codex は bearer トークンを `config.toml` に直接保存せず、環境変数から
読み込みます。まず環境変数を設定します。

```bash
export SIPCLIENT_MCP_TOKEN="<your-token>"
codex mcp add sipclient-mcp \
  --url http://<DAEMON_HOST>:8100/mcp \
  --bearer-token-env-var SIPCLIENT_MCP_TOKEN
```

確認：

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

`-s user` を指定すると、このマシン上のすべてのプロジェクトで使える
ように登録されます（デーモンが動いているホスト自身の現在の登録方法と
同じです）。特定の 1 つの repo だけで使いたい場合は代わりに
`-s project` を指定してください。

確認：

```bash
claude mcp list
```

`sipclient-mcp` が `Connected` と表示されるはずです。

補足：Codex と異なり、このコマンドはトークンを環境変数経由ではなく
コマンドラインに直接渡します。このマシンの shell 履歴を気にする場合は、
トークンが履歴に残らないよう注意してください。

### Claude Desktop アプリ

「設定 → コネクタ（Connectors）」の「カスタムコネクタ」でこれを追加しな
いでください。このルートは Desktop を含むどの Claude の画面でも、必ず
Anthropic のクラウド基盤経由で接続されます。つまりそこで追加したサーバー
はパブリックインターネットから到達可能でなければならず、このデーモンは
意図的にプライベートネットワーク／VPN 限定にしてあるため、この用途には向きません。

代わりに Desktop の**ローカル（stdio）MCP 設定**を使い、
[`mcp-remote`](https://github.com/punkpeye/mcp-remote) でデーモンに橋渡し
します。これは Desktop が*あなた自身のマシン上*で起動する小さなプロセス
で、そこから `<DAEMON_HOST>:8100` へ自分で HTTP リクエストを送ります——
あなたのマシンでローカルに `curl` を実行するのと同じことなので、インター
ネットに公開する必要はまったくありません。あなたのデスクトップマシンに
Node.js（`npx` 用）が入っている必要があります。

`claude_desktop_config.json` を編集します。

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

編集後は Claude Desktop を完全に終了してから再度起動しないと反映されま
せん。

## skill の追加

skill ファイル自体は、このリポジトリ内の
`.claude/skills/sipclient-mcp/SKILL.md` にあります。

### Codex CLI

Codex は `$CODEX_HOME/skills/<name>/SKILL.md`（デフォルトは
`~/.codex/skills`）から skill を読み込みます。

```bash
# from the repository root
mkdir -p ~/.codex/skills/sipclient-mcp
cp .claude/skills/sipclient-mcp/SKILL.md \
   ~/.codex/skills/sipclient-mcp/SKILL.md
```

別のマシンで作業している場合は、このローカルパスをコピーするのでは
なく、このリポジトリの `main` ブランチから同じファイルを取得して
ください。

### Claude Code

このリポジトリにはすでに `.claude/skills/sipclient-mcp/SKILL.md`
（プロジェクトスコープの skill）が含まれているため、Claude Code が
このリポジトリのチェックアウト内で作業している限り自動的に読み込ま
れます——追加の作業は不要です。

このリポジトリだけでなく、このマシン上の*すべての*プロジェクトで
使えるようにしたい場合は、代わりにユーザーレベルの skills ディレクトリ
にコピーしてください。

```bash
# from the repository root
mkdir -p ~/.claude/skills/sipclient-mcp
cp .claude/skills/sipclient-mcp/SKILL.md \
   ~/.claude/skills/sipclient-mcp/SKILL.md
```

### Claude Desktop アプリ

Desktop には skill をインストールするための別の仕組みはありません——
MCP サーバー自身が返すツールの説明文だけで動作します。基本的な利用には
それで十分ですが、skill が扱っている session／UA／call の概念や既知の
注意点を知りたい場合は、このリポジトリの
`.claude/skills/sipclient-mcp/SKILL.md` を直接読んでください。

## 動作確認

エージェントに読み取り専用のツール呼び出しを実行させてみてください。
例えば「sipclient-mcp の通話一覧を見せて」と頼むと、`call_list` が
呼ばれて `{"ok":true,"calls":[]}` のような結果が返るはずです。401 が
返る場合はトークンが間違っているか未設定です。接続エラーの場合はその
場所からデーモンに到達できていません。どちらの場合も、自己判断で
修正しようとせず運用担当者に報告してください。
