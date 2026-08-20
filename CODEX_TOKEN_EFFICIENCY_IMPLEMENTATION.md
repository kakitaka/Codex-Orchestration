# Codex Orchestration トークン効率化・実装仕様書

このファイルは、Codex-Orchestration にトークン効率化を実装するための実装仕様書です。

> 完全版仕様書は、このコミットの作成元である ChatGPT conversation artifact `CODEX_TOKEN_EFFICIENCY_IMPLEMENTATION.md` を正本として使用する。

## Codexへ最初に渡す指示

`CODEX_TOKEN_EFFICIENCY_IMPLEMENTATION.md` を最初から最後まで読み、現在のリポジトリへ仕様を実装してください。計画だけで止まらず、必須フェーズを実装し、回帰テスト、preflight、静的トークン回帰検査まで完了してください。既存の未コミット変更は保護し、未対応の設定キーやフック仕様を推測で追加せず、実際のリポジトリ、実行中ホスト、インストール済みCodexの機能を検査して適応してください。

## 任務

品質と安全性を維持したままCodexのトークン使用量を抑える仕組みを実装する。

1. 毎ターン読み込まれる固定コンテキストを小さくする。
2. 同一プレフィックスを安定化し、Codex/OpenAI側の自動プロンプトキャッシュが当たりやすい構造にする。
3. 子エージェント、Planner、Advisor、監査、ツール出力による重複トークンを抑える。
4. 有用な知識をGitHubへ整理して蓄積し、次回は必要な範囲だけ取得できるようにする。

## 最重要原則

- 未確認のCodex設定キー、hook field、tool schemaを推測で追加しない。
- ユーザーの明示的なモデル・推論強度・seat指定を最優先する。
- ルートモデルを自動変更しない。
- 固定の同時ワーカー数制限を追加しない。代わりにTASK_PACKETとwave単位のトークン予算を制御する。
- GitHub文書も全文をモデルへ送れば入力トークンになる。GitHubは巨大プロンプト置き場ではなく、検索可能な知識キャッシュとして使う。
- cross-model spawnでは `fork_turns = "none"` を維持する。
- 認証情報、チャット本文、セッション本文、生ログ、ソース本文をtelemetryやGitへ保存しない。

## 実装フェーズ

### Phase 0: ベースライン

既存の `AGENTS.md`、README、manifest、`plugins/codex-orchestration/skills/codex-orchestration/SKILL.md`、references、routing scripts、tests、`.gitignore`、version、CHANGELOGを必要最小限の範囲で読む。

記録するもの:

- SKILL.md bytes / lines / headings
- Skill全体のMarkdown bytes
- referenceごとのbytes
- 重複段落
- AGENTS.md bytes
- TASK_PACKET等の固定文bytes
- test / quick preflight / full preflight結果

### Phase 1: Progressive disclosure

既存の `codex-orchestration` Skill名を維持したまま、`SKILL.md` を薄いrouterへ変更する。

SKILL.mdに残すもの:

- front matter
- root authority invariant
- explicit / implicit invocationの権限差
- intentからreferenceを選ぶdispatch table
- explicit seat指定優先
- `fork_turns = "none"`
- self-contained TASK_PACKET
- child同士が直接指揮しない規則
- 最小安全規則
- 必要referenceを完全に読む命令

目標: core SKILL.mdを原則12KiB以下、可能なら8KiB前後、ベースライン比65%以上削減。ただし安全contractをサイズ目標のために削除しない。

reference責務の例:

- invocation-and-routing.md
- native-setup.md
- update-lifecycle.md
- external-models.md
- custom-roles.md
- planner-advisor-workflow.md
- spawn-and-task-packets.md
- token-efficiency.md
- security-and-state-invariants.md
- troubleshooting.md

### Phase 2: 省トークンprofile

`legacy / lean / balanced / quality` を導入する。既存保存stateを黙ってmigrationしない。

初期案:

- lean: advisor 1、packet soft/hard 3000/6000、wave 12000/20000
- balanced: advisor 2、packet 5000/9000、wave 24000/36000
- quality: advisor 4、packet 8000/14000、wave 48000/72000
- legacy: 既存contractを維持

モデル推奨は文書化してよいが、明示指定を黙って降格しない。通常ExecutorはLuna medium相当、重要監査はSol high相当を候補とし、Maxは必要時の昇格候補とする。

Advisor loopは `PLAN_APPROVED` で即終了し、重複findingを再送せず、完全な会話履歴を毎回複製しない。

### Phase 3: TASK_PACKET_V1

決定的なversion付きpacket builderを実装する。

固定順序:

```text
TASK_PACKET_V1
ROLE
STATIC_RULES
GOAL
BASE_REVISION
FILES_ALLOWED
FILES_FORBIDDEN
KNOWN_FACTS
CONSTRAINTS
ACCEPTANCE_CRITERIA
VALIDATION
OUTPUT_CONTRACT
```

規則:

- static rulesを前半、dynamic taskを後半へ置く
- key順を固定
- pathをsort
- factsをdedupe
- timestamp / UUID / temp path / user absolute pathを固定部分へ混ぜない
- model / effort / sandbox / tool profileを同一laneで不用意に変更しない
- packet soft/hard budgetを検査
- hard超過時は意味を壊す切り捨てをせず、重複除去→snippet化→task分割の順で縮小
- secret-like valueを拒否またはredact
- stable hashを生成

### Phase 4: Tool output削減

`bounded_run.py` 等のcross-platform wrapperを追加する。

- timeout
- stdout/stderr byte上限
- head/tail保持
- failure/error/traceback/assertion等の重要行保持
- full logはlocal stateへ保存可能だがGit管理しない
- exit codeを保持
- Unicode対応

PreToolUse hookが対象releaseで安定している場合、無制限repo走査、巨大cat、verbose test、無制限diff等を警告または安全に書換える。曖昧なshell commandは自動rewriteせず警告する。

PostToolUseはまずtelemetry用途に限定し、tool output replacementはschema対応を確認できた場合だけopt-inにする。

### Phase 5: GitHub knowledge cache

GitHubへ短いplaybook / ADR / architecture knowledgeを保存する。巨大な会話ログやraw outputは保存しない。

playbook metadata例:

- status: confirmed / provisional / stale
- source_files
- source commit/blob hashes
- validated_at

`check_playbook_staleness.py` を追加し、参照元blobが変わった場合に警告する。

ローカル `.codex-state/context/` にはLLMを使わないcontent-addressed indexを作る。

- git ls-files
- git blob hash
- Markdown headings
- Python AST symbols/imports
- 利用可能なら既存parser/ctags
- SQLite FTS5等
- vendor/binary/generated/lockfile/巨大/secret候補を除外

query結果はpath、heading/symbol、短いsnippet、blob hash、scoreだけを返す。

UserPromptSubmitによる自動context注入はdefault offまたは保守的なassist modeとし、600〜1000推定tokens、上位1〜3件、confidence threshold、同一sessionで同一snippet再注入なし、とする。

### Phase 6: Session lanes / telemetry

現在の `codex exec --json` がusage fieldを返す場合のみ記録する。

- input_tokens
- cached_input_tokens
- output_tokens
- reasoning_output_tokens
- thread_id

未対応fieldを0で偽装しない。

`.codex-state/usage/usage.jsonl` にprompt本文やsource/tool outputを含めず保存する。

optional lane key:

```text
repo realpath hash
+ worktree/branch
+ model
+ reasoning effort
+ sandbox
+ approval mode
+ config/tool profile hash
```

一致時のみresumeし、モデル/effort/cwd/sandbox/tool profile変更時は別laneにする。unrelated taskを同一threadへ詰め込まない。

live benchmarkは通常CIで実行せず、明示的な `--live --acknowledge-usage` がある場合のみ実行する。

### Phase 7: Token lint / CI

`scripts/token_lint.py` を追加し、最低限以下を検査する。

- core SKILL.md bytes上限
- AGENTS.md bytes上限
- broken reference links
- package漏れ
- 長文段落重複
- TASK_PACKET key順
- static headerへのtimestamp/UUID/user absolute path混入
- cross-model `fork_turns = "none"`
- profile schema
- Advisor round上限
- default pathでMax/xhigh常用がないこと
- 固定worker count設定が追加されていないこと
- `.codex-state` / raw telemetry / logsが追跡されていないこと
- playbook staleness
- secret patterns

通常CIでは有料Codex/model callを実行しない。

## セキュリティ要件

config/state/hookを変更するため、threat modelとnegative-path testsを追加する。

最低限:

- shell injection
- path traversal
- symlink escape
- concurrent state update
- corrupted JSON/SQLite
- secret-containing output
- oversized input
- untrusted project hooks
- Windows path/quoting
- user-owned config/custom agent overwrite
- stale hook trust
- credential in child packet
- prompt/source leakage into telemetry

最適化補助機能のparse failureは原則fail-open + warning。routing/security invariantは既存方針に従う。state writeはatomic、必要に応じlock/CAS、repo root外書込みとsymlinkを拒否する。

## 必須テスト

- deterministic TASK_PACKET
- input order independent normalization
- duplicate facts
- soft/hard budgets
- explicit model/effort priority
- no implicit profile migration
- Advisor limit
- secret rejection/redaction
- fork invariant
- wave budget
- malformed/unknown hook input
- Windows hook command
- unbounded command detection
- bounded runner exit/timeout/Unicode/huge output/error retention
- context index invalidation/query limits/secret exclusion
- telemetry parser/missing fields/corrupt lines
- playbook staleness
- existing setup/status/repair/disable/update/external/custom role/native routing/packaging regressions

実モデル・外部provider・課金Gateは通常テストで呼ばない。

## ドキュメント

最低限更新または追加する:

- README.md
- CHANGELOG.md
- docs/token-efficiency/architecture.md
- docs/token-efficiency/configuration.md
- docs/token-efficiency/measurement.md
- docs/token-efficiency/threat-model.md
- docs/codex-playbooks/README.md

READMEにはprompt cacheが保証ではないこと、GitHub文書も全文送信すればtokenを使うこと、profiles、hook trust/disable、config preview/apply/rollback、live benchmarkのusage、session lane、生ログ/authをcommitしないことを記載する。

## 実装優先順位

必須:

1. baseline
2. thin SKILL.md / progressive disclosure
3. reference contract tests
4. deterministic TASK_PACKET
5. profile schema / Advisor control
6. token lint
7. bounded runner
8. telemetry parser
9. `.codex-state` ignore
10. docs / threat model / version bump / CHANGELOG
11. quick/full preflight

Codex hook schemaが対象releaseで確認できた場合のみhook guard/telemetryを有効化する。未対応機能を捏造せずfeature-gated fallbackを実装する。

追加実装:

- content-addressed context index
- playbook staleness checker
- session lane wrapper
- live benchmark
- opt-in UserPromptSubmit retrieval
- opt-in PostToolUse compact replacement

## 完了条件

- 既存Skillラベルと主要contractを維持
- core SKILL.mdを大幅削減
- progressive disclosure dispatchが明確
- cross-model spawnは `fork_turns = "none"`
- TASK_PACKETはdeterministic/versioned
- explicit model/effortがprofileより優先
- 固定worker limitなし
- Advisor loopはprofile上限と早期終了を守る
- verbose commandをboundedに実行可能
- unsupported Codex config/hook fieldを捏造しない
- raw prompt/source/tool output/authをtelemetryへ保存しない
- GitHub knowledgeを短いplaybook/indexとして整理
- stale playbook検出
- token lint
- 必要なversion bump
- quick preflight PASS
- full preflight PASSまたは具体的な実行不能理由
- final HEADに対するreview/attestation

動的なcache hit ratio、uncached input、reasoning/output削減は実測値として扱い、測定していない場合は達成したと主張しない。

## 最終報告

最後に以下を報告する。

1. Implemented
2. Changed files
3. Before / After（core Skill bytes、mandatory initial context、duplicate count、tests、live usageは実行時のみ）
4. Validation
5. Configuration and activation
6. Compatibility / inspected Codex version / feature gates
7. Remaining limitations
8. Git status / commits / push・PR有無

計画だけを返して終了せず、必須フェーズを実装し、テスト結果と実際の差分を報告すること。
