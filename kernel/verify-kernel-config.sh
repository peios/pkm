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

require_enabled() {
	local key=$1

	if ! grep -Eq "^${key}=[ym]\$" "$config"; then
		die "required config ${key} is neither =y nor =m"
	fi
}

# Asserts a symbol is not built at all: either explicitly "# not set" or
# absent (invisible because its dependencies are off). Use for symbols a
# profile may not even expose — require_unset demands the literal marker
# and would fail on those.
require_disabled() {
	local key=$1

	if grep -Eq "^${key}=" "$config"; then
		die "required disabled config ${key} is enabled"
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
# Yama would decide ptrace attach ahead of the KACS hook (PEI-689).
require_unset CONFIG_SECURITY_YAMA
require_set CONFIG_LSM '"landlock,lockdown,integrity,pkm"'
require_set CONFIG_STRICT_DEVMEM y
require_set CONFIG_MODULE_SIG_FORCE y
require_unset CONFIG_SECURITY_LOADPIN

# Firmware signature verification (PEI-493) ships in log mode for 2026.8;
# enforcement is a deliberate flip, made here and in pkm.fragment together.
require_unset CONFIG_SECURITY_PKM_FIRMWARE_SIG_ENFORCE
# test.fwsig needs the loader's self-test module. The kunit profile flattens
# modules to built-in, so either form is acceptable.
require_enabled CONFIG_TEST_FIRMWARE

# Module signing must be ML-DSA-65, matching KACS binary signing, and the
# authattrs waiver must accompany it. Dropping the waiver without moving to
# OpenSSL 4.x makes every module load fail at boot — catch that here rather
# than on hardware.
require_set CONFIG_MODULE_SIG_ALL y
require_set CONFIG_MODULE_SIG_KEY_TYPE_MLDSA_65 y
require_set CONFIG_PKCS7_WAIVE_AUTHATTRS_REJECTION_FOR_MLDSA y

# OPENSSL_SUPPORTS_ML_DSA is a live probe of the build root's openssl
# (`openssl list -key-managers | grep -q ML-DSA-87`). Without it the ML-DSA key
# types silently vanish from the choice rather than failing, so assert it.
require_set CONFIG_OPENSSL_SUPPORTS_ML_DSA y

# The signing key must be provisioned, never left at the default
# certs/signing_key.pem — certs/Makefile treats that as a request to
# autogenerate an ephemeral keypair, which breaks reproducibility.
if grep -Fxq 'CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"' "$config"; then
	die "CONFIG_MODULE_SIG_KEY is the autogenerating default; provision a key"
fi
if ! grep -qE '^CONFIG_MODULE_SIG_KEY=".+"' "$config"; then
	die "CONFIG_MODULE_SIG_KEY is empty"
fi

# Lockdown must actually be enforcing; compiled-in-but-none is the default and
# is indistinguishable from absent at runtime.
require_set CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY y
require_set CONFIG_SECURITY_LOCKDOWN_LSM_EARLY y

# --- PNP: Peios Network Policy (PEI-598) ---
# The engine must be in, its machinery built-in (built-in PNP calls these
# symbols on the packet path), and the replaced policy frontends must stay
# out — a stray nf_tables would be a second, unratified policy surface.
require_set CONFIG_PEIOS_PNP y
require_set CONFIG_NETFILTER y
require_set CONFIG_NETFILTER_INGRESS y
require_set CONFIG_NETFILTER_EGRESS y
require_set CONFIG_NF_CONNTRACK y
require_disabled CONFIG_NF_TABLES
require_disabled CONFIG_NETFILTER_XTABLES
require_disabled CONFIG_NETFILTER_NETLINK_QUEUE
require_disabled CONFIG_NETFILTER_NETLINK_LOG
require_disabled CONFIG_BRIDGE_NETFILTER
