# mib-oid-parser

SNMP の MIB ファイルから OID を抽出・解決する、**Python 標準ライブラリのみ**で動作するツールです。

## 特徴

- 外部ライブラリ不要
- Tokenizer + Parser + Resolver ベース
- 複数 MIB ファイルの同時解析に対応
- `IMPORTS ... FROM ...;` を見て依存 MIB をディレクトリから探索可能
- `DESCRIPTION` を抽出して出力可能
- `table / json / csv` 出力に対応

## 対応している宣言

- `OBJECT IDENTIFIER`
- `OBJECT-TYPE`
- `MODULE-IDENTITY`
- `NOTIFICATION-TYPE`

## 使い方

### 単一 MIB を解析

```bash
python mib_oid_extractor.py MY-MIB.txt
```

### JSON / CSV 出力

```bash
python mib_oid_extractor.py MY-MIB.txt --format json
python mib_oid_extractor.py MY-MIB.txt --format csv
```

### 宣言種別で絞り込み

```bash
python mib_oid_extractor.py MY-MIB.txt --only-kind OBJECT-TYPE
```

### 依存 MIB をディレクトリから探索

```bash
python mib_oid_extractor.py MY-MIB.txt --mib-dir ./mibs
python mib_oid_extractor.py MY-MIB.txt --mib-dir ./mibs --mib-dir /usr/share/snmp/mibs
```

### 依存ディレクトリの再帰探索を無効化

```bash
python mib_oid_extractor.py MY-MIB.txt --mib-dir ./mibs --no-recursive
```

### 未解決モジュール・未解決宣言を表示

```bash
python mib_oid_extractor.py MY-MIB.txt --mib-dir ./mibs --show-unresolved
```

## 出力項目

- `name`
- `kind`
- `oid` (`json` のみ)
- `oid_str`
- `module_name`
- `source`
- `description`

## DESCRIPTION について

`OBJECT-TYPE` / `MODULE-IDENTITY` / `NOTIFICATION-TYPE` に含まれる `DESCRIPTION "..."` を抽出して出力します。

- `table`: 改行を 1 行に整形して表示
- `json/csv`: なるべく元の内容を保持

## サンプル

```bash
python mib_oid_extractor.py tests/fixtures/EXAMPLE-DEVICE-MIB.txt --mib-dir tests/fixtures --format json
```

## テスト実行

Python 標準ライブラリの `unittest` で実行できます。

```bash
python -m unittest discover -s tests -p 'test_*.py'
```

## テスト内容

- `DESCRIPTION` 抽出
- OID 解決
- `IMPORTS` 経由の依存 MIB 読み込み
- `OBJECT IDENTIFIER` / `OBJECT-TYPE` / `MODULE-IDENTITY` / `NOTIFICATION-TYPE` の解析

## 制限事項

- ���全な ASN.1 / SMI 実装ではありません
- 非常に特殊なベンダー独自 MIB では解釈できない場合があります
- `IMPORTS` は依存モジュール探索用途の簡易解析です
- `DESCRIPTION` 以外の `STATUS` / `REFERENCE` / `SYNTAX` / `MAX-ACCESS` は現時点では未抽出です

## 今後の拡張候補

- `STATUS` / `REFERENCE` / `SYNTAX` / `MAX-ACCESS` 抽出
- 出力整形の改善
- テストケース追加
- より広い ASN.1 記法対応
