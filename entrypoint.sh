#!/bin/sh
# cf-probe 容器入口:从环境变量生成/合并 /data/config.conf,然后前台运行。
# 设计目标:
#   - 首次启动:根据默认值 + 已设置的环境变量写出完整配置。
#   - 再次启动:只 upsert 本次显式设置的环境变量对应行,保留其余(含服务端历史下发的字段)。
#   - 容器内彻底禁用二进制自更新:无论环境/旧配置为何,AUTO_UPDATE 恒为 0。
# 环境变量名与 config.conf 的键名保持一致。
set -eu
umask 077

DATA_DIR="${CF_PROBE_DATA_DIR:-/data}"
TARGET_CONFIG="${DATA_DIR}/config.conf"
BIN="/app/cf-probe"

[ "${SECRET+x}" != x ] && [ "${TERMINAL_TOKEN+x}" != x ] || {
	printf '%s\n' '[ERROR] Legacy credentials removed; recreate container with NODE_TOKEN.' >&2
	exit 1
}
[ ! -L "$DATA_DIR" ] && [ ! -L "$TARGET_CONFIG" ] || exit 1
[ ! -e "$TARGET_CONFIG" ] || [ -f "$TARGET_CONFIG" ] || exit 1
mkdir -p "$DATA_DIR"
CONFIG="$(mktemp "${DATA_DIR}/.node-config.XXXXXX")"
trap 'rm -f "$CONFIG"' EXIT INT TERM
if [ -f "$TARGET_CONFIG" ]; then cp "$TARGET_CONFIG" "$CONFIG"; fi
chmod 600 "$CONFIG"
if grep -Eq '^(SECRET|TERMINAL_TOKEN)=' "$CONFIG"; then
	[ "${NODE_TOKEN+x}" = x ] || {
		printf '%s\n' '[ERROR] Legacy configuration: reinstall with NODE_TOKEN.' >&2
		exit 1
	}
	# Explicit migration retains collection settings, never obsolete credentials.
	sed '/^SECRET=/d; /^TERMINAL_TOKEN=/d' "$CONFIG" > "$CONFIG.clean"
	mv "$CONFIG.clean" "$CONFIG"
fi

# 记录某键在本次启动是否被显式设置(用于首启必填校验)。
env_is_set() {
	# shellcheck disable=SC2140
	eval "[ \"\${$1+set}\" = set ]"
}

# 幂等 upsert:存在则替换该行,不存在则追加;写值统一用 KEY="value" 格式。
upsert() {
	key="$1"
	value="$2"
	case "$value" in *'"'*|*'\'*|*'
'*) printf '%s\n' '[ERROR] Unsafe configuration value.' >&2; exit 1 ;; esac
	tmp="$(mktemp "${DATA_DIR}/.config.XXXXXX")"
	if [ -f "$CONFIG" ] && grep -q "^${key}=" "$CONFIG"; then
		awk -v k="$key" -v v="$value" '
			BEGIN { done = 0 }
			{
				pos = index($0, "=")
				name = (pos > 0) ? substr($0, 1, pos - 1) : $0
				if (name == k) { print k "=\"" v "\""; done = 1 }
				else { print $0 }
			}
			END { if (done == 0) print k "=\"" v "\"" }
		' "$CONFIG" > "$tmp"
	else
		if [ -f "$CONFIG" ]; then
			cp "$CONFIG" "$tmp"
			# 确保以换行结尾再追加,避免和末行粘连。
			if [ -s "$tmp" ] && [ "$(tail -c1 "$tmp" | wc -l)" -eq 0 ]; then
				printf '\n' >> "$tmp"
			fi
		else
			: > "$tmp"
		fi
		printf '%s="%s"\n' "$key" "$value" >> "$tmp"
	fi
	mv "$tmp" "$CONFIG"
}

first_run=0
if [ ! -f "$TARGET_CONFIG" ]; then
	first_run=1
	: > "$CONFIG"
fi

# 首次创建时补齐一份可读的默认值;已存在的配置保持原样,不做整体覆盖。
if [ "$first_run" -eq 1 ]; then
	upsert COLLECT_INTERVAL "0"
	upsert REPORT_INTERVAL "60"
	upsert RESET_DAY "1"
	upsert CONNECTION_MODE "auto"
	upsert PING_MODE "tcp"
	upsert CONFIG_MD5 "none"
fi

# 用环境变量覆盖对应键(仅覆盖本次显式设置的)。
for key in SERVER_ID NODE_TOKEN WORKER_URL COLLECT_INTERVAL REPORT_INTERVAL \
	CT_NODE CU_NODE CM_NODE BD_NODE NODE_1 NODE_2 NODE_3 NODE_4 \
	INTERFACE RESET_DAY CONNECTION_MODE PING_MODE UPDATE_PROXY; do
	if env_is_set "$key"; then
		eval "value=\${$key}"
		upsert "$key" "$value"
	fi
done

# 自定义 UA 只作首次引导:配置里没有该键时才写入环境变量值。
# 服务端会通过 X-Ua / WSS ack 下发并落盘;若每次启动都用旧环境变量覆盖,
# 面板改过 UA 的容器一重启就回滚成旧值,配合 /update 的防火墙规则会永久离线。
if env_is_set UA && ! grep -q '^UA=' "$CONFIG"; then
	eval "value=\${UA}"
	upsert "UA" "$value"
fi

# 容器内强制关闭自动更新(此键不受服务端下发影响,持久有效)。
upsert AUTO_UPDATE "0"
upsert TERMINAL_ENABLED "0"

# 首次启动必填校验。
if [ "$first_run" -eq 1 ]; then
	missing=""
	for key in SERVER_ID NODE_TOKEN WORKER_URL; do
		if ! grep -q "^${key}=\"[^\"]" "$CONFIG"; then
			missing="${missing} ${key}"
		fi
	done
	if [ -n "$missing" ]; then
		cat >&2 <<EOF
[ERROR] 首次启动缺少必填配置:${missing}
请通过环境变量提供,例如:
  docker run -d --name cf-probe --restart=unless-stopped --network=host \\
    -v cf-probe-data:/data \\
    -e SERVER_ID=xxxx -e NODE_TOKEN=<64-lowercase-hex> -e WORKER_URL=https://example.com/update \\
    <image>
EOF
		exit 1
	fi
fi

node_token="$(sed -n 's/^NODE_TOKEN="\([^"]*\)"$/\1/p' "$CONFIG")"
[ "${#node_token}" = 64 ] || { printf '%s\n' '[ERROR] Invalid NODE_TOKEN.' >&2; exit 1; }
case "$node_token" in *[!a-f0-9]*) printf '%s\n' '[ERROR] Invalid NODE_TOKEN.' >&2; exit 1 ;; esac
worker_url="$(sed -n 's/^WORKER_URL="\([^"]*\)"$/\1/p' "$CONFIG")"
case "$worker_url" in *'@'*|*'?'*|*'#'*) exit 1 ;; https://*/update) ;; *) printf '%s\n' '[ERROR] HTTPS /update endpoint required.' >&2; exit 1 ;; esac
mv "$CONFIG" "$TARGET_CONFIG"
CONFIG="$TARGET_CONFIG"
trap - EXIT INT TERM

# 透传调试开关(可选)。
debug_args=""
if env_is_set CF_PROBE_DEBUG; then
	debug_args="-debug=${CF_PROBE_DEBUG}"
fi

exec "$BIN" run -config "$CONFIG" ${debug_args}
