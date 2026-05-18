#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 <kernel-config>" >&2
	exit 2
fi

config=$1

die() {
	echo "verify-kernel-config: $*" >&2
	exit 1
}

require_config_file() {
	if [[ ! -f "$config" ]]; then
		die "kernel config missing: $config"
	fi
}

require_set() {
	local key=$1
	local value=$2

	if ! grep -Fxq "${key}=${value}" "$config"; then
		die "required config ${key}=${value} not present"
	fi
}

require_unset() {
	local key=$1

	if ! grep -Fxq "# ${key} is not set" "$config"; then
		die "required disabled config ${key} is not set"
	fi
}

require_config_file

require_set CONFIG_SECURITY_PKM y
require_set CONFIG_RUST y
require_unset CONFIG_SECURITY_SELINUX
require_unset CONFIG_SECURITY_APPARMOR
require_unset CONFIG_SECURITY_SMACK
require_unset CONFIG_SECURITY_TOMOYO
require_unset CONFIG_BPF_LSM
require_set CONFIG_LSM '"landlock,lockdown,yama,integrity,pkm"'
require_set CONFIG_STRICT_DEVMEM y
require_set CONFIG_MODULE_SIG_FORCE y
