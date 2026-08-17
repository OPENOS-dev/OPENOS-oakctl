#!/usr/bin/env bash
# OAK 密钥管理工具 (oakctl)
# 用途: 生成/解析 .oak 密钥文件 (openssl), 注册公钥到 /proc/oak/subjects。
#
# 用法:
#   oakctl.sh genkey <name> [algorithm]     # 生成 <name>.oak(公钥) + .private/<name>.key.oak(私钥)
#   oakctl.sh parse <file.oak>              # 显示 .oak 字段
#   oakctl.sh pubkey-hex <name>             # 输出公钥 DER hex (用于 proc 注册)
#   oakctl.sh fingerprint <name>            # 计算公钥指纹
#
# 依赖: openssl (系统) + 内核 OAK LSM (/proc/oak)。

set -euo pipefail
KEYS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../KEYS" && pwd)"
PRIV_DIR="$KEYS_DIR/.private"
ALGO="${2:-rsa-4096}"

usage() {
  echo "用法: oakctl.sh <genkey|parse|pubkey-hex|fingerprint> <name> [algorithm]"
  exit 1
}

# 解析 .oak 键值
oak_get() { sed -n "s/^$2 = //p" "$1" | head -n1; }

genkey() {
  local name="$1"
  [ -n "$name" ] || usage
  mkdir -p "$PRIV_DIR"
  local priv="$PRIV_DIR/$name.key.oak"
  local pub="$KEYS_DIR/$name.oak"

  # 用临时 PEM 生成, 再转 .oak
  local tmp_priv="$PRIV_DIR/.$name.pem" tmp_pub="$KEYS_DIR/.$name.pub.pem"
  case "$ALGO" in
    rsa-4096)    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$tmp_priv" >/dev/null 2>&1
                 openssl pkey -in "$tmp_priv" -pubout -out "$tmp_pub" >/dev/null 2>&1 ;;
    rsa-2048)    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp_priv" >/dev/null 2>&1
                 openssl pkey -in "$tmp_priv" -pubout -out "$tmp_pub" >/dev/null 2>&1 ;;
    ed25519)     openssl genpkey -algorithm ED25519 -out "$tmp_priv" >/dev/null 2>&1
                 openssl pkey -in "$tmp_priv" -pubout -out "$tmp_pub" >/dev/null 2>&1 ;;
    *) echo "不支持的算法: $ALGO"; exit 1 ;;
  esac

  # 私钥写入 .key.oak (文本 PEM)
  cat > "$priv" <<EOF
# OAK 私钥: $name (受保护, 不进镜像)
type = private
name = $name
algorithm = $ALGO
private = $(sed 's/^/LINE /' "$tmp_priv" | base64 | tr -d '\n')
EOF

  # 公钥 DER hex + 指纹
  local der_hex pub_hex fp
  der_hex="$(openssl pkey -in "$tmp_priv" -pubout -outform DER 2>/dev/null | xxd -p | tr -d '\n')"
  pub_hex="$der_hex"
  fp="$(printf '%s' "$der_hex" | openssl dgst -sha256 | awk '{print $2}')"

  cat > "$pub" <<EOF
# OAK 公钥: $name
type = subject
name = $name
purpose = $name
algorithm = $ALGO
public = $pub_hex
fingerprint = $fp
EOF
  rm -f "$tmp_priv" "$tmp_pub"
  echo "已生成: $pub (公钥) + $priv (私钥)"
}

parse() { [ -n "$1" ] || usage; echo "== $1 =="; cat "$1"; }

pubkey_hex() { oak_get "$KEYS_DIR/$1.oak" public; }
fingerprint() { oak_get "$KEYS_DIR/$1.oak" fingerprint; }

cmd="${1:-}"; name="${2:-}"
case "$cmd" in
  genkey)        genkey "$name" ;;
  parse)         parse "$name" ;;
  pubkey-hex)    pubkey_hex "$name" ;;
  fingerprint)   fingerprint "$name" ;;
  *) usage ;;
esac
