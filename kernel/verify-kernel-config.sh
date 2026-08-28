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
require_unset CONFIG_SECURITY_LOADPIN

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
