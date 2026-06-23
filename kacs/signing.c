// SPDX-License-Identifier: GPL-2.0-only

#include <crypto/sha2.h>
#include <crypto/sig.h>

#include <linux/byteorder/generic.h>
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/xattr.h>

#include "builtin_signing_keys.h"
#include "signing.h"
#include "token_runtime.h"

static void pkm_kacs_signing_material_clear(
	struct pkm_kacs_signing_material *out)
{
	memset(out, 0, sizeof(*out));
}

static bool pkm_kacs_signing_range_valid(size_t offset, size_t len,
					 size_t file_len)
{
	return offset <= file_len && len <= file_len - offset;
}

static bool pkm_kacs_signing_elf_range_valid(u64 offset, u64 len,
					     size_t file_len,
					     size_t *offset_out,
					     size_t *len_out)
{
	size_t offset_size;
	size_t len_size;

	if (offset > SIZE_MAX || len > SIZE_MAX)
		return false;

	offset_size = (size_t)offset;
	len_size = (size_t)len;
	if (!pkm_kacs_signing_range_valid(offset_size, len_size, file_len))
		return false;

	*offset_out = offset_size;
	*len_out = len_size;
	return true;
}

static bool pkm_kacs_signing_section_name_eq(const u8 *strtab,
					     size_t strtab_len, u32 name_offset,
					     const char *expected)
{
	size_t expected_len = strlen(expected);
	size_t remaining;

	if (name_offset >= strtab_len)
		return false;

	remaining = strtab_len - name_offset;
	if (remaining < expected_len + 1)
		return false;
	if (memcmp(strtab + name_offset, expected, expected_len) != 0)
		return false;

	return strtab[name_offset + expected_len] == '\0';
}

static void pkm_kacs_signing_hash_buffer(const u8 *file_bytes,
					 size_t file_len, size_t zero_offset,
					 size_t zero_len,
					 u8 hash[SHA256_DIGEST_SIZE])
{
	static const u8 zeros[SHA256_BLOCK_SIZE];
	struct sha256_ctx ctx;
	size_t zero_end;

	sha256_init(&ctx);
	if (zero_len == 0) {
		if (file_len != 0)
			sha256_update(&ctx, file_bytes, file_len);
		sha256_final(&ctx, hash);
		return;
	}

	zero_end = zero_offset + zero_len;
	if (zero_offset != 0)
		sha256_update(&ctx, file_bytes, zero_offset);
	while (zero_len != 0) {
		size_t chunk = min_t(size_t, zero_len, sizeof(zeros));

		sha256_update(&ctx, zeros, chunk);
		zero_len -= chunk;
	}
	if (zero_end < file_len)
		sha256_update(&ctx, file_bytes + zero_end,
			      file_len - zero_end);
	sha256_final(&ctx, hash);
}

static bool pkm_kacs_signing_blob_valid(const u8 *blob, size_t blob_len)
{
	return blob && blob_len == PKM_KACS_SIGNING_BLOB_LEN &&
	       blob[0] == PKM_KACS_SIGNING_VERSION;
}

static int pkm_kacs_signing_probe_xattr_buffer(
	const u8 *file_bytes, size_t file_len, const u8 *xattr_sig,
	size_t xattr_sig_len, struct pkm_kacs_signing_material *out)
{
	if (xattr_sig_len == 0)
		return 0;
	if (!xattr_sig)
		return -EINVAL;
	if (!pkm_kacs_signing_blob_valid(xattr_sig, xattr_sig_len))
		return 0;

	out->source = PKM_KACS_SIGNING_SOURCE_XATTR;
	memcpy(out->signature, xattr_sig + 1, PKM_KACS_SIGNING_SIGNATURE_LEN);
	pkm_kacs_signing_hash_buffer(file_bytes, file_len, 0, 0, out->hash);
	return 0;
}

static bool pkm_kacs_signing_buffer_is_elf(const u8 *file_bytes,
					   size_t file_len)
{
	return file_len >= SELFMAG &&
	       memcmp(file_bytes, ELFMAG, SELFMAG) == 0;
}

static int pkm_kacs_signing_probe_elf_buffer(
	const u8 *file_bytes, size_t file_len,
	struct pkm_kacs_signing_material *out, bool *committed_out)
{
	const u8 *strtab;
	Elf64_Shdr shstr = {};
	Elf64_Ehdr ehdr = {};
	size_t shdrs_offset;
	size_t shdrs_len;
	size_t strtab_offset;
	size_t strtab_len;
	u16 shnum;
	u16 shentsize;
	u16 shstrndx;
	u16 i;

	*committed_out = false;
	if (!pkm_kacs_signing_buffer_is_elf(file_bytes, file_len))
		return 0;
	if (file_len < sizeof(ehdr)) {
		*committed_out = true;
		return 0;
	}

	memcpy(&ehdr, file_bytes, sizeof(ehdr));
	if (ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
	    ehdr.e_ident[EI_VERSION] != EV_CURRENT) {
		*committed_out = true;
		return 0;
	}

	shnum = ehdr.e_shnum;
	shentsize = ehdr.e_shentsize;
	shstrndx = ehdr.e_shstrndx;
	if (shnum == 0)
		return 0;
	if (shentsize != sizeof(Elf64_Shdr) ||
	    shstrndx == SHN_UNDEF || shstrndx >= shnum) {
		*committed_out = true;
		return 0;
	}

	if (ehdr.e_shoff > SIZE_MAX) {
		*committed_out = true;
		return 0;
	}
	shdrs_offset = (size_t)ehdr.e_shoff;
	if (shnum > (SIZE_MAX / sizeof(Elf64_Shdr))) {
		*committed_out = true;
		return 0;
	}
	shdrs_len = (size_t)shnum * sizeof(Elf64_Shdr);
	if (!pkm_kacs_signing_range_valid(shdrs_offset, shdrs_len, file_len)) {
		*committed_out = true;
		return 0;
	}

	memcpy(&shstr,
	       file_bytes + shdrs_offset +
		       ((size_t)shstrndx * sizeof(Elf64_Shdr)),
	       sizeof(shstr));
	if (!pkm_kacs_signing_elf_range_valid(shstr.sh_offset, shstr.sh_size,
					      file_len, &strtab_offset,
					      &strtab_len)) {
		*committed_out = true;
		return 0;
	}
	strtab = file_bytes + strtab_offset;

	for (i = 0; i < shnum; i++) {
		Elf64_Shdr shdr = {};
		size_t sig_offset;
		size_t sig_len;

		memcpy(&shdr,
		       file_bytes + shdrs_offset +
			       ((size_t)i * sizeof(Elf64_Shdr)),
		       sizeof(shdr));
		if (!pkm_kacs_signing_section_name_eq(
			    strtab, strtab_len, shdr.sh_name,
			    PKM_KACS_SIGNING_ELF_SECTION))
			continue;

		*committed_out = true;
		if (shdr.sh_type != SHT_PROGBITS ||
		    shdr.sh_size != PKM_KACS_SIGNING_BLOB_LEN ||
		    !pkm_kacs_signing_elf_range_valid(shdr.sh_offset,
						      shdr.sh_size, file_len,
						      &sig_offset,
						      &sig_len) ||
		    !pkm_kacs_signing_blob_valid(file_bytes + sig_offset,
						 sig_len))
			return 0;

		out->source = PKM_KACS_SIGNING_SOURCE_ELF;
		memcpy(out->signature, file_bytes + sig_offset + 1,
		       PKM_KACS_SIGNING_SIGNATURE_LEN);
		pkm_kacs_signing_hash_buffer(file_bytes, file_len, sig_offset,
					     sig_len, out->hash);
		return 0;
	}

	return 0;
}

static int __maybe_unused pkm_kacs_signing_probe_buffer(
	const u8 *file_bytes, size_t file_len, const u8 *xattr_sig,
	size_t xattr_sig_len, struct pkm_kacs_signing_material *out)
{
	bool committed = false;
	int ret;

	if (!out)
		return -EINVAL;
	if (file_len != 0 && !file_bytes)
		return -EINVAL;
	if (xattr_sig_len != 0 && !xattr_sig)
		return -EINVAL;

	pkm_kacs_signing_material_clear(out);
	ret = pkm_kacs_signing_probe_elf_buffer(file_bytes, file_len, out,
						&committed);
	if (ret || committed)
		return ret;

	return pkm_kacs_signing_probe_xattr_buffer(file_bytes, file_len,
						   xattr_sig, xattr_sig_len,
						   out);
}

struct pkm_kacs_signing_reader {
	void *ctx;
	int (*size)(void *ctx, size_t *size_out);
	int (*read)(void *ctx, size_t offset, u8 *dst, size_t len);
	int (*xattr)(void *ctx, u8 *dst, size_t dst_len, size_t *actual_len);
};

static bool pkm_kacs_signing_reader_valid(
	const struct pkm_kacs_signing_reader *reader)
{
	return reader && reader->size && reader->read && reader->xattr;
}

static int pkm_kacs_signing_reader_exact(
	const struct pkm_kacs_signing_reader *reader, size_t offset, u8 *dst,
	size_t len)
{
	if (len == 0)
		return 0;
	if (!reader || !reader->read || !dst)
		return -EINVAL;

	return reader->read(reader->ctx, offset, dst, len);
}

static int pkm_kacs_signing_hash_reader(
	const struct pkm_kacs_signing_reader *reader, size_t file_len,
	size_t zero_offset, size_t zero_len, u8 hash[SHA256_DIGEST_SIZE])
{
	static const u8 zeros[SHA256_BLOCK_SIZE];
	struct sha256_ctx ctx;
	size_t zero_end;
	size_t pos = 0;
	u8 *buf;
	int ret = 0;

	if (!hash || !pkm_kacs_signing_reader_valid(reader))
		return -EINVAL;
	if (zero_len != 0 &&
	    !pkm_kacs_signing_range_valid(zero_offset, zero_len, file_len))
		return -EINVAL;

	buf = kmalloc(PKM_KACS_SIGNING_HASH_CHUNK, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	sha256_init(&ctx);
	zero_end = zero_offset + zero_len;
	while (pos < file_len) {
		size_t chunk;

		if (zero_len != 0 && pos >= zero_offset && pos < zero_end) {
			chunk = min_t(size_t, zero_end - pos, file_len - pos);
			while (chunk != 0) {
				size_t zero_chunk =
					min_t(size_t, chunk, sizeof(zeros));

				sha256_update(&ctx, zeros, zero_chunk);
				pos += zero_chunk;
				chunk -= zero_chunk;
			}
			continue;
		}

		chunk = min_t(size_t, PKM_KACS_SIGNING_HASH_CHUNK,
			      file_len - pos);
		if (zero_len != 0 && pos < zero_offset &&
		    chunk > zero_offset - pos)
			chunk = zero_offset - pos;

		ret = pkm_kacs_signing_reader_exact(reader, pos, buf, chunk);
		if (ret)
			goto out_free;

		sha256_update(&ctx, buf, chunk);
		pos += chunk;
	}

	sha256_final(&ctx, hash);

out_free:
	kfree(buf);
	return ret;
}

static int pkm_kacs_signing_reader_section_name_eq(
	const struct pkm_kacs_signing_reader *reader, size_t file_len,
	size_t strtab_offset, size_t strtab_len, u32 name_offset,
	bool *match_out)
{
	char name[sizeof(PKM_KACS_SIGNING_ELF_SECTION)];
	size_t name_pos;
	int ret;

	if (!match_out)
		return -EINVAL;

	*match_out = false;
	if (!pkm_kacs_signing_range_valid(name_offset, sizeof(name),
					  strtab_len))
		return 0;
	if (strtab_offset > SIZE_MAX - name_offset)
		return -EOVERFLOW;

	name_pos = strtab_offset + name_offset;
	if (!pkm_kacs_signing_range_valid(name_pos, sizeof(name), file_len))
		return -EOVERFLOW;

	ret = pkm_kacs_signing_reader_exact(reader, name_pos, (u8 *)name,
					    sizeof(name));
	if (ret)
		return ret;

	*match_out = memcmp(name, PKM_KACS_SIGNING_ELF_SECTION,
			    sizeof(name)) == 0;
	return 0;
}

static bool pkm_kacs_signing_reader_is_elf(
	const struct pkm_kacs_signing_reader *reader, size_t file_len,
	bool *invalid_out)
{
	u8 magic[SELFMAG];
	int ret;

	*invalid_out = false;
	if (file_len < SELFMAG)
		return false;

	ret = pkm_kacs_signing_reader_exact(reader, 0, magic, sizeof(magic));
	if (ret) {
		*invalid_out = true;
		return false;
	}

	return memcmp(magic, ELFMAG, SELFMAG) == 0;
}

static int pkm_kacs_signing_probe_elf_reader(
	const struct pkm_kacs_signing_reader *reader, size_t file_len,
	struct pkm_kacs_signing_material *out, bool *committed_out)
{
	Elf64_Shdr shstr = {};
	Elf64_Ehdr ehdr = {};
	size_t shdrs_offset;
	size_t shdrs_len;
	size_t strtab_offset;
	size_t strtab_len;
	bool invalid = false;
	u16 shnum;
	u16 shentsize;
	u16 shstrndx;
	u16 i;
	int ret;

	*committed_out = false;
	if (!pkm_kacs_signing_reader_is_elf(reader, file_len, &invalid)) {
		*committed_out = invalid;
		return 0;
	}
	if (file_len < sizeof(ehdr)) {
		*committed_out = true;
		return 0;
	}

	ret = pkm_kacs_signing_reader_exact(reader, 0, (u8 *)&ehdr,
					    sizeof(ehdr));
	if (ret) {
		*committed_out = true;
		return 0;
	}

	if (ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
	    ehdr.e_ident[EI_VERSION] != EV_CURRENT) {
		*committed_out = true;
		return 0;
	}

	shnum = ehdr.e_shnum;
	shentsize = ehdr.e_shentsize;
	shstrndx = ehdr.e_shstrndx;
	if (shnum == 0)
		return 0;
	if (shentsize != sizeof(Elf64_Shdr) ||
	    shstrndx == SHN_UNDEF || shstrndx >= shnum) {
		*committed_out = true;
		return 0;
	}

	if (ehdr.e_shoff > SIZE_MAX) {
		*committed_out = true;
		return 0;
	}
	shdrs_offset = (size_t)ehdr.e_shoff;
	if (shnum > (SIZE_MAX / sizeof(Elf64_Shdr))) {
		*committed_out = true;
		return 0;
	}
	shdrs_len = (size_t)shnum * sizeof(Elf64_Shdr);
	if (!pkm_kacs_signing_range_valid(shdrs_offset, shdrs_len, file_len)) {
		*committed_out = true;
		return 0;
	}

	ret = pkm_kacs_signing_reader_exact(
		reader,
		shdrs_offset + ((size_t)shstrndx * sizeof(Elf64_Shdr)),
		(u8 *)&shstr, sizeof(shstr));
	if (ret) {
		*committed_out = true;
		return 0;
	}

	if (!pkm_kacs_signing_elf_range_valid(shstr.sh_offset, shstr.sh_size,
					      file_len, &strtab_offset,
					      &strtab_len)) {
		*committed_out = true;
		return 0;
	}

	for (i = 0; i < shnum; i++) {
		Elf64_Shdr shdr = {};
		size_t sig_offset;
		size_t sig_len;
		bool name_match = false;
		u8 blob[PKM_KACS_SIGNING_BLOB_LEN];

		ret = pkm_kacs_signing_reader_exact(
			reader, shdrs_offset + ((size_t)i * sizeof(Elf64_Shdr)),
			(u8 *)&shdr, sizeof(shdr));
		if (ret) {
			*committed_out = true;
			return 0;
		}

		ret = pkm_kacs_signing_reader_section_name_eq(
			reader, file_len, strtab_offset, strtab_len,
			shdr.sh_name, &name_match);
		if (ret) {
			*committed_out = true;
			return 0;
		}
		if (!name_match)
			continue;

		*committed_out = true;
		if (shdr.sh_type != SHT_PROGBITS ||
		    shdr.sh_size != PKM_KACS_SIGNING_BLOB_LEN ||
		    !pkm_kacs_signing_elf_range_valid(shdr.sh_offset,
						      shdr.sh_size, file_len,
						      &sig_offset,
						      &sig_len))
			return 0;

		ret = pkm_kacs_signing_reader_exact(reader, sig_offset, blob,
						    sizeof(blob));
		if (ret || !pkm_kacs_signing_blob_valid(blob, sig_len))
			return 0;

		ret = pkm_kacs_signing_hash_reader(reader, file_len, sig_offset,
						   sig_len, out->hash);
		if (ret)
			return 0;

		out->source = PKM_KACS_SIGNING_SOURCE_ELF;
		memcpy(out->signature, blob + 1,
		       PKM_KACS_SIGNING_SIGNATURE_LEN);
		return 0;
	}

	return 0;
}

static int pkm_kacs_signing_probe_xattr_reader(
	const struct pkm_kacs_signing_reader *reader, size_t file_len,
	struct pkm_kacs_signing_material *out)
{
	u8 blob[PKM_KACS_SIGNING_BLOB_LEN];
	size_t actual_len = 0;
	int ret;

	ret = reader->xattr(reader->ctx, blob, sizeof(blob), &actual_len);
	if (ret || actual_len == 0)
		return 0;
	if (!pkm_kacs_signing_blob_valid(blob, actual_len))
		return 0;

	ret = pkm_kacs_signing_hash_reader(reader, file_len, 0, 0, out->hash);
	if (ret)
		return 0;

	out->source = PKM_KACS_SIGNING_SOURCE_XATTR;
	memcpy(out->signature, blob + 1, PKM_KACS_SIGNING_SIGNATURE_LEN);
	return 0;
}

static int pkm_kacs_signing_probe_reader(
	const struct pkm_kacs_signing_reader *reader,
	struct pkm_kacs_signing_material *out)
{
	size_t file_len = 0;
	size_t final_len = 0;
	bool committed = false;
	int ret;

	if (!out || !pkm_kacs_signing_reader_valid(reader))
		return -EINVAL;

	pkm_kacs_signing_material_clear(out);
	ret = reader->size(reader->ctx, &file_len);
	if (ret)
		return 0;

	ret = pkm_kacs_signing_probe_elf_reader(reader, file_len, out,
						&committed);
	if (ret)
		return ret;
	if (!committed && out->source == PKM_KACS_SIGNING_SOURCE_NONE) {
		ret = pkm_kacs_signing_probe_xattr_reader(reader, file_len,
							  out);
		if (ret)
			return ret;
	}

	ret = reader->size(reader->ctx, &final_len);
	if (ret || final_len != file_len)
		pkm_kacs_signing_material_clear(out);

	return 0;
}

static int pkm_kacs_signing_file_size(void *ctx, size_t *size_out)
{
	struct file *file = ctx;
	loff_t size;

	if (!file || !file_inode(file) || !size_out)
		return -EINVAL;

	size = i_size_read(file_inode(file));
	if (size < 0 || (u64)size > (u64)SIZE_MAX)
		return -EOVERFLOW;

	*size_out = (size_t)size;
	return 0;
}

static int pkm_kacs_signing_file_read(void *ctx, size_t offset, u8 *dst,
				      size_t len)
{
	struct file *file = ctx;
	ssize_t read_len;
	loff_t pos;

	if (!file || !dst)
		return -EINVAL;
	if ((u64)offset > (u64)LLONG_MAX)
		return -EOVERFLOW;

	pos = (loff_t)offset;
	read_len = kernel_read(file, dst, len, &pos);
	if (read_len < 0)
		return (int)read_len;
	if ((size_t)read_len != len)
		return -EIO;

	return 0;
}

static int pkm_kacs_signing_file_xattr(void *ctx, u8 *dst, size_t dst_len,
				       size_t *actual_len)
{
	struct file *file = ctx;
	struct dentry *dentry;
	struct inode *inode;
	ssize_t ret;

	if (!file || !dst || !actual_len)
		return -EINVAL;

	*actual_len = 0;
	dentry = file_dentry(file);
	inode = file_inode(file);
	if (!dentry || !inode)
		return -EINVAL;

	ret = __vfs_getxattr(dentry, inode, PKM_KACS_SIGNING_XATTR_NAME, NULL,
			     0);
	if (ret == -ENODATA || ret == -EOPNOTSUPP)
		return 0;
	if (ret < 0)
		return (int)ret;
	if ((u64)ret > (u64)SIZE_MAX)
		return -EOVERFLOW;

	*actual_len = (size_t)ret;
	if ((size_t)ret != PKM_KACS_SIGNING_BLOB_LEN)
		return 0;
	if (dst_len < PKM_KACS_SIGNING_BLOB_LEN)
		return -ERANGE;

	ret = __vfs_getxattr(dentry, inode, PKM_KACS_SIGNING_XATTR_NAME, dst,
			     PKM_KACS_SIGNING_BLOB_LEN);
	if (ret < 0)
		return (int)ret;
	if (ret != PKM_KACS_SIGNING_BLOB_LEN)
		return -EIO;

	return 0;
}

int pkm_kacs_signing_probe_file(
	struct file *file, struct pkm_kacs_signing_material *out)
{
	struct pkm_kacs_signing_reader reader = {
		.ctx = file,
		.size = pkm_kacs_signing_file_size,
		.read = pkm_kacs_signing_file_read,
		.xattr = pkm_kacs_signing_file_xattr,
	};

	return pkm_kacs_signing_probe_reader(&reader, out);
}

struct pkm_kacs_signing_key_entry {
	u8 public_key[PKM_KACS_SIGNING_PUBLIC_KEY_LEN];
	__le32 pip_type;
	__le32 pip_trust;
} __packed;

#ifdef CONFIG_SECURITY_PKM_KUNIT
static const struct pkm_kacs_signing_key_entry pkm_kacs_builtin_signing_keys[]
	__used __section(".pkm_kacs_builtin_signing_keys") = {
	{
		.public_key = {
			0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe,
			0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0, 0x99,
			0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f,
			0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8,
		},
		.pip_type = cpu_to_le32(PKM_KACS_PIP_TYPE_PROTECTED),
		.pip_trust = cpu_to_le32(PKM_KACS_PIP_TRUST_PEIOS_TCB),
	},
	{ { 0 }, 0, 0 },
};
#else
static const struct pkm_kacs_signing_key_entry pkm_kacs_builtin_signing_keys[]
	__used __section(".pkm_kacs_builtin_signing_keys") = {
	PKM_KACS_BUILTIN_SIGNING_KEY_TABLE
};
#endif

typedef bool (*pkm_kacs_signing_verify_fn)(
	const u8 public_key[PKM_KACS_SIGNING_PUBLIC_KEY_LEN],
	const u8 hash[SHA256_DIGEST_SIZE],
	const u8 signature[PKM_KACS_SIGNING_SIGNATURE_LEN], void *ctx);

static void pkm_kacs_signing_trust_clear(
	struct pkm_kacs_signing_trust_result *out)
{
	memset(out, 0, sizeof(*out));
}

static bool pkm_kacs_signing_key_entry_zero(
	const struct pkm_kacs_signing_key_entry *entry)
{
	return memchr_inv(entry, 0, sizeof(*entry)) == NULL;
}

static bool pkm_kacs_signing_key_tier_valid(u32 pip_type, u32 pip_trust)
{
	return pip_type == PKM_KACS_PIP_TYPE_PROTECTED &&
	       pip_trust == PKM_KACS_PIP_TRUST_PEIOS_TCB;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
int pkm_kacs_kunit_builtin_signing_key_table_shape(u32 *usable_count_out,
						   u32 *terminated_out)
{
	size_t usable_count = 0;
	bool terminated = false;
	size_t i;

	if (!usable_count_out || !terminated_out)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(pkm_kacs_builtin_signing_keys); i++) {
		u32 pip_type;
		u32 pip_trust;

		if (pkm_kacs_signing_key_entry_zero(
			    &pkm_kacs_builtin_signing_keys[i])) {
			terminated = true;
			break;
		}

		pip_type = le32_to_cpu(pkm_kacs_builtin_signing_keys[i].pip_type);
		pip_trust =
			le32_to_cpu(pkm_kacs_builtin_signing_keys[i].pip_trust);
		if (!pkm_kacs_signing_key_tier_valid(pip_type, pip_trust))
			return -EINVAL;

		usable_count++;
	}

	*usable_count_out = usable_count;
	*terminated_out = terminated ? 1U : 0U;
	return 0;
}
#endif
static int __maybe_unused pkm_kacs_signing_verify_with_keys(
	const struct pkm_kacs_signing_material *material,
	const struct pkm_kacs_signing_key_entry *keys, size_t key_count,
	pkm_kacs_signing_verify_fn verify, void *verify_ctx,
	struct pkm_kacs_signing_trust_result *out)
{
	size_t usable_count = 0;
	bool terminated = false;
	size_t i;

	if (!material || !out)
		return -EINVAL;

	pkm_kacs_signing_trust_clear(out);
	if (material->source == PKM_KACS_SIGNING_SOURCE_NONE)
		return 0;
	if (!keys || key_count == 0 || !verify)
		return -EINVAL;

	for (i = 0; i < key_count; i++) {
		u32 pip_type;
		u32 pip_trust;

		if (pkm_kacs_signing_key_entry_zero(&keys[i])) {
			terminated = true;
			break;
		}

		pip_type = le32_to_cpu(keys[i].pip_type);
		pip_trust = le32_to_cpu(keys[i].pip_trust);
		if (!pkm_kacs_signing_key_tier_valid(pip_type, pip_trust))
			return -EINVAL;

		usable_count++;
	}
	if (!terminated)
		return -EINVAL;

	for (i = 0; i < usable_count; i++) {
		u32 pip_type;
		u32 pip_trust;

		if (!verify(keys[i].public_key, material->hash,
			    material->signature, verify_ctx))
			continue;

		pip_type = le32_to_cpu(keys[i].pip_type);
		pip_trust = le32_to_cpu(keys[i].pip_trust);
		out->verified = 1;
		out->pip_type = pip_type;
		out->pip_trust = pip_trust;
		return 0;
	}

	return 0;
}

static bool __maybe_unused pkm_kacs_signing_crypto_verify(
	const u8 public_key[PKM_KACS_SIGNING_PUBLIC_KEY_LEN],
	const u8 hash[SHA256_DIGEST_SIZE],
	const u8 signature[PKM_KACS_SIGNING_SIGNATURE_LEN], void *ctx)
{
	struct crypto_sig *tfm;
	int ret;

	(void)ctx;

	tfm = crypto_alloc_sig("ed25519", 0, 0);
	if (IS_ERR(tfm))
		return false;

	ret = crypto_sig_set_pubkey(tfm, public_key,
				    PKM_KACS_SIGNING_PUBLIC_KEY_LEN);
	if (!ret)
		ret = crypto_sig_verify(tfm, signature,
					PKM_KACS_SIGNING_SIGNATURE_LEN, hash,
					SHA256_DIGEST_SIZE);

	crypto_free_sig(tfm);
	return ret == 0;
}

int pkm_kacs_signing_verify_builtin(
	const struct pkm_kacs_signing_material *material,
	struct pkm_kacs_signing_trust_result *result)
{
	return pkm_kacs_signing_verify_with_keys(
		material, pkm_kacs_builtin_signing_keys,
		ARRAY_SIZE(pkm_kacs_builtin_signing_keys),
		pkm_kacs_signing_crypto_verify, NULL, result);
}

void pkm_kacs_exec_pip_from_material(
	const struct pkm_kacs_signing_material *material, u32 *pip_type_out,
	u32 *pip_trust_out)
{
	struct pkm_kacs_signing_trust_result result;
	int ret;

	if (!pip_type_out || !pip_trust_out)
		return;

	*pip_type_out = 0;
	*pip_trust_out = 0;
	if (!material)
		return;

	ret = pkm_kacs_signing_verify_with_keys(
		material, pkm_kacs_builtin_signing_keys,
		ARRAY_SIZE(pkm_kacs_builtin_signing_keys),
		pkm_kacs_signing_crypto_verify, NULL, &result);
	if (ret || !result.verified)
		return;

	*pip_type_out = result.pip_type;
	*pip_trust_out = result.pip_trust;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
struct pkm_kacs_kunit_signing_reader_ctx {
	const struct pkm_kacs_kunit_signing_reader_args *args;
	u32 size_calls;
};

struct pkm_kacs_kunit_signing_verify_ctx {
	const struct pkm_kacs_signing_key_entry *keys;
	size_t key_count;
	u32 match_key_index;
	u32 match_enabled;
};

static int pkm_kacs_kunit_signing_reader_size(void *ctx, size_t *size_out)
{
	struct pkm_kacs_kunit_signing_reader_ctx *reader_ctx = ctx;
	const struct pkm_kacs_kunit_signing_reader_args *args;

	if (!reader_ctx || !reader_ctx->args || !size_out)
		return -EINVAL;

	args = reader_ctx->args;
	reader_ctx->size_calls++;
	if (args->use_final_file_len && reader_ctx->size_calls > 1)
		*size_out = args->final_file_len;
	else
		*size_out = args->file_len;
	return 0;
}

static int pkm_kacs_kunit_signing_reader_read(void *ctx, size_t offset,
					      u8 *dst, size_t len)
{
	struct pkm_kacs_kunit_signing_reader_ctx *reader_ctx = ctx;
	const struct pkm_kacs_kunit_signing_reader_args *args;

	if (!reader_ctx || !reader_ctx->args || !dst)
		return -EINVAL;

	args = reader_ctx->args;
	if (args->fail_reads)
		return -EIO;
	if (len == 0)
		return 0;
	if (len != 0 && !args->file_bytes)
		return -EINVAL;
	if (!pkm_kacs_signing_range_valid(offset, len, args->file_len))
		return -EIO;

	memcpy(dst, args->file_bytes + offset, len);
	return 0;
}

static int pkm_kacs_kunit_signing_reader_xattr(void *ctx, u8 *dst,
					       size_t dst_len,
					       size_t *actual_len)
{
	struct pkm_kacs_kunit_signing_reader_ctx *reader_ctx = ctx;
	const struct pkm_kacs_kunit_signing_reader_args *args;

	if (!reader_ctx || !reader_ctx->args || !dst || !actual_len)
		return -EINVAL;

	args = reader_ctx->args;
	*actual_len = args->xattr_sig_len;
	if (args->fail_xattr)
		return -EIO;
	if (args->xattr_sig_len == 0)
		return 0;
	if (args->xattr_sig_len != PKM_KACS_SIGNING_BLOB_LEN)
		return 0;
	if (!args->xattr_sig || dst_len < PKM_KACS_SIGNING_BLOB_LEN)
		return -EINVAL;

	memcpy(dst, args->xattr_sig, PKM_KACS_SIGNING_BLOB_LEN);
	return 0;
}

static bool pkm_kacs_kunit_signing_fake_verify(
	const u8 public_key[PKM_KACS_SIGNING_PUBLIC_KEY_LEN],
	const u8 hash[SHA256_DIGEST_SIZE],
	const u8 signature[PKM_KACS_SIGNING_SIGNATURE_LEN], void *ctx)
{
	struct pkm_kacs_kunit_signing_verify_ctx *verify_ctx = ctx;

	(void)hash;
	(void)signature;

	if (!verify_ctx || !verify_ctx->match_enabled ||
	    verify_ctx->match_key_index >= verify_ctx->key_count)
		return false;

	return memcmp(public_key,
		      verify_ctx->keys[verify_ctx->match_key_index].public_key,
		      PKM_KACS_SIGNING_PUBLIC_KEY_LEN) == 0;
}

static int pkm_kacs_kunit_copy_signing_keys(
	const struct pkm_kacs_kunit_signing_key_entry *keys, size_t key_count,
	struct pkm_kacs_signing_key_entry **key_table_out)
{
	struct pkm_kacs_signing_key_entry *key_table = NULL;
	size_t i;

	if (!key_table_out)
		return -EINVAL;
	*key_table_out = NULL;
	if (key_count != 0 && !keys)
		return -EINVAL;

	if (key_count != 0) {
		key_table = kcalloc(key_count, sizeof(*key_table), GFP_KERNEL);
		if (!key_table)
			return -ENOMEM;
	}

	for (i = 0; i < key_count; i++) {
		memcpy(key_table[i].public_key, keys[i].public_key,
		       sizeof(key_table[i].public_key));
		key_table[i].pip_type = cpu_to_le32(keys[i].pip_type);
		key_table[i].pip_trust = cpu_to_le32(keys[i].pip_trust);
	}

	*key_table_out = key_table;
	return 0;
}

int pkm_kacs_signing_material_from_kunit_probe(
	const struct pkm_kacs_kunit_signing_probe *material,
	struct pkm_kacs_signing_material *material_out)
{
	if (!material || !material_out)
		return -EINVAL;
	if (material->source != PKM_KACS_SIGNING_SOURCE_NONE &&
	    material->source != PKM_KACS_SIGNING_SOURCE_ELF &&
	    material->source != PKM_KACS_SIGNING_SOURCE_XATTR)
		return -EINVAL;

	memset(material_out, 0, sizeof(*material_out));
	material_out->source = material->source;
	memcpy(material_out->signature, material->signature,
	       sizeof(material_out->signature));
	memcpy(material_out->hash, material->hash, sizeof(material_out->hash));
	return 0;
}

int pkm_kacs_kunit_probe_signing_material(
	const u8 *file_bytes, size_t file_len, const u8 *xattr_sig,
	size_t xattr_sig_len, struct pkm_kacs_kunit_signing_probe *out)
{
	struct pkm_kacs_signing_material material;
	int ret;

	if (!out)
		return -EINVAL;

	ret = pkm_kacs_signing_probe_buffer(file_bytes, file_len, xattr_sig,
					    xattr_sig_len, &material);
	if (ret)
		return ret;

	memset(out, 0, sizeof(*out));
	out->source = material.source;
	memcpy(out->signature, material.signature, sizeof(out->signature));
	memcpy(out->hash, material.hash, sizeof(out->hash));
	return 0;
}

int pkm_kacs_kunit_verify_signing_material(
	const struct pkm_kacs_kunit_signing_probe *material,
	const struct pkm_kacs_kunit_signing_key_entry *keys, size_t key_count,
	u32 match_key_index, u32 match_enabled,
	struct pkm_kacs_kunit_signing_verify_out *out)
{
	struct pkm_kacs_kunit_signing_verify_ctx verify_ctx;
	struct pkm_kacs_signing_trust_result result;
	struct pkm_kacs_signing_material material_in;
	struct pkm_kacs_signing_key_entry *key_table = NULL;
	int ret;

	if (!material || !out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	memset(&material_in, 0, sizeof(material_in));
	material_in.source = material->source;
	memcpy(material_in.signature, material->signature,
	       sizeof(material_in.signature));
	memcpy(material_in.hash, material->hash, sizeof(material_in.hash));

	ret = pkm_kacs_kunit_copy_signing_keys(keys, key_count, &key_table);
	if (ret)
		return ret;

	verify_ctx.keys = key_table;
	verify_ctx.key_count = key_count;
	verify_ctx.match_key_index = match_key_index;
	verify_ctx.match_enabled = match_enabled;
	ret = pkm_kacs_signing_verify_with_keys(
		&material_in, key_table, key_count,
		pkm_kacs_kunit_signing_fake_verify, &verify_ctx, &result);
	if (ret)
		goto out_free;

	out->verified = result.verified;
	out->pip_type = result.pip_type;
	out->pip_trust = result.pip_trust;

out_free:
	kfree(key_table);
	return ret;
}

int pkm_kacs_kunit_verify_signing_material_crypto(
	const struct pkm_kacs_kunit_signing_probe *material,
	const struct pkm_kacs_kunit_signing_key_entry *keys, size_t key_count,
	struct pkm_kacs_kunit_signing_verify_out *out)
{
	struct pkm_kacs_signing_trust_result result;
	struct pkm_kacs_signing_material material_in;
	struct pkm_kacs_signing_key_entry *key_table = NULL;
	int ret;

	if (!material || !out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	memset(&material_in, 0, sizeof(material_in));
	material_in.source = material->source;
	memcpy(material_in.signature, material->signature,
	       sizeof(material_in.signature));
	memcpy(material_in.hash, material->hash, sizeof(material_in.hash));

	ret = pkm_kacs_kunit_copy_signing_keys(keys, key_count, &key_table);
	if (ret)
		return ret;

	ret = pkm_kacs_signing_verify_with_keys(
		&material_in, key_table, key_count,
		pkm_kacs_signing_crypto_verify, NULL, &result);
	if (ret)
		goto out_free;

	out->verified = result.verified;
	out->pip_type = result.pip_type;
	out->pip_trust = result.pip_trust;

out_free:
	kfree(key_table);
	return ret;
}

int pkm_kacs_kunit_determine_exec_pip_from_signing_material(
	const struct pkm_kacs_kunit_signing_probe *material,
	struct pkm_kacs_kunit_signing_verify_out *out)
{
	struct pkm_kacs_signing_material material_in;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	int ret;

	if (!out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	ret = pkm_kacs_signing_material_from_kunit_probe(material, &material_in);
	if (ret)
		return ret;

	pkm_kacs_exec_pip_from_material(&material_in, &pip_type, &pip_trust);
	out->verified = pip_type != 0 || pip_trust != 0;
	out->pip_type = pip_type;
	out->pip_trust = pip_trust;
	return 0;
}

int pkm_kacs_kunit_signed_exec_pin_from_signing_material(
	const struct pkm_kacs_kunit_signing_probe *material, u32 *pinned_out)
{
	struct pkm_kacs_signing_material material_in;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	int ret;

	if (!pinned_out)
		return -EINVAL;

	*pinned_out = 0;
	ret = pkm_kacs_signing_material_from_kunit_probe(material, &material_in);
	if (ret)
		return ret;

	pkm_kacs_exec_pip_from_material(&material_in, &pip_type, &pip_trust);
	*pinned_out = (pip_type != 0 || pip_trust != 0) ? 1U : 0U;
	return 0;
}

int pkm_kacs_kunit_probe_signing_reader(
	const struct pkm_kacs_kunit_signing_reader_args *args,
	struct pkm_kacs_kunit_signing_probe *out)
{
	struct pkm_kacs_kunit_signing_reader_ctx ctx = {
		.args = args,
	};
	struct pkm_kacs_signing_reader reader = {
		.ctx = &ctx,
		.size = pkm_kacs_kunit_signing_reader_size,
		.read = pkm_kacs_kunit_signing_reader_read,
		.xattr = pkm_kacs_kunit_signing_reader_xattr,
	};
	struct pkm_kacs_signing_material material;
	int ret;

	if (!args || !out)
		return -EINVAL;

	ret = pkm_kacs_signing_probe_reader(&reader, &material);
	if (ret)
		return ret;

	memset(out, 0, sizeof(*out));
	out->source = material.source;
	memcpy(out->signature, material.signature, sizeof(out->signature));
	memcpy(out->hash, material.hash, sizeof(out->hash));
	return 0;
}
#endif
