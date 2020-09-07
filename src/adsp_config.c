/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2020 Intel Corporation. All rights reserved.
 *
 * Author: Karol Trzcinski <karolx.trzcinski@linux.intel.com>
 */

#include "rimage/sof/user/manifest.h"
#include "rimage/adsp_config.h"
#include "rimage/plat_auth.h"
#include "rimage/manifest.h"
#include "rimage/rimage.h"
#include "rimage/cse.h"
#include "rimage/css.h"
#include "toml.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define DUMP_KEY_FMT "   %20s: "
#define DUMP(fmt, ...) fprintf(stdout, fmt "\n", ##__VA_ARGS__)
#define DUMP_KEY(key, fmt, ...) DUMP(DUMP_KEY_FMT fmt, key, ##__VA_ARGS__)

static inline bool check_config_version(int major, int minor, const int64_t *version)
{
	return version[0] == major && version[1] == minor;
}

static int log_err(int err_code, const char *msg, ...)
{
	va_list vl;

	va_start(vl, msg);
	vfprintf(stderr, msg, vl);
	va_end(vl);
	return err_code;
}

static int err_malloc(const char *key)
{
	return log_err(-ENOMEM, "error: malloc failed during parsing key '%s'\n", key);
}

static int err_key_not_found(const char *key)
{
	return log_err(-ENOKEY, "error: '%s' not found\n", key);
}

static int err_key_parse_error(const char *key)
{
	return log_err(-EINVAL, "error: key '%s' parsing error\n", key);
}

static uint32_t parse_uint32_hex_key(const toml_table_t *table, const char *key, int64_t def,
				     int *error)
{
	toml_raw_t raw;
	char *temp_s;
	int64_t val;
	int ret;

	raw = toml_raw_in(table, key);
	if (!raw) {
		if (def < 0 || def > UINT32_MAX) {
			*error = err_key_not_found(key);
		} else {
			*error = 0;
			return (uint32_t)def;
		}
	}
	ret = toml_rtos(raw, &temp_s);
	if (ret < 0) {
		*error = err_key_parse_error(key);
		return UINT32_MAX;
	}
	val = strtol(temp_s, 0, 16);
	free(temp_s);
	if (errno < 0 || val < 0 || val > UINT32_MAX) {
		*error = err_key_parse_error(key);
		return UINT32_MAX;
	}
	*error = 0;
	return (uint32_t)val;
}

static int parse_uint32_key(const toml_table_t *table, const char *key, int64_t def, int *error)
{
	toml_raw_t raw;
	int64_t val;
	int ret;

	raw = toml_raw_in(table, key);
	if (!raw) {
		if (def < 0 || def > UINT32_MAX) {
			*error = err_key_not_found(key);
		} else {
			*error = 0;
			return (uint32_t)def;
		}
	}
	ret = toml_rtoi(raw, &val);
	if (ret < 0 || val < 0 || val > UINT32_MAX) {
		*error = err_key_parse_error(key);
		return UINT32_MAX;
	}
	*error = 0;
	return (uint32_t)val;
}

static void parse_str_key(const toml_table_t *table, const char *key, char *dst, int capacity, int *error)
{
	toml_raw_t raw;
	char *temp_s;
	int len;
	int ret;

	raw = toml_raw_in(table, key);
	if (!raw) {
		*error = err_key_not_found(key);
		return;
	}
	ret = toml_rtos(raw, &temp_s);
	if (ret < 0) {
		*error = err_key_parse_error(key);
		return;
	}
	len = strlen(temp_s);
	if (len > capacity) {
		*error = log_err(-EINVAL, "Too long input for key '%s' (%d > %d)\n", key, len, capacity);
		free(temp_s);
		return;
	}
	strncpy(dst, temp_s, len);
	free(temp_s);
	*error = 0;
}

static int parse_mem_cse(const toml_table_t *toml, struct CsePartitionDirHeader *hdr,
			 struct CsePartitionDirEntry *out)
{
	toml_array_t *cse_entry_array;
	toml_table_t *cse_entry;
	toml_table_t *cse;
	int ret;
	int i;

	cse = toml_table_in(toml, "cse");
	if (!cse)
		return err_key_not_found("cse");

	/* non-configurable fields */
	hdr->header_marker = CSE_HEADER_MAKER;
	hdr->header_length = sizeof(struct CsePartitionDirHeader);

	/* configurable fields */
	hdr->header_version = parse_uint32_key(cse, "header_version", -1, &ret);
	if (ret < 0)
		return ret;

	hdr->entry_version = parse_uint32_key(cse, "entry_version", -1, &ret);
	if (ret < 0)
		return ret;
	
	parse_str_key(cse, "partition_name", (char *)hdr->partition_name,
		      sizeof(hdr->partition_name), &ret);
	if (ret < 0)
		return ret;
	
	cse_entry_array = toml_array_in(cse, "entry");
	if (!cse_entry_array)
		return err_key_not_found("entry");

	if (toml_array_kind(cse_entry_array) != 't' ||
	    toml_array_nelem(cse_entry_array) != MAN_CSE_PARTS)
		return err_key_parse_error("entry");
	
	for (i = 0; i < toml_array_nelem(cse_entry_array); ++i) {
		cse_entry = toml_table_at(cse_entry_array, i);
		if (!cse_entry)
			return err_key_parse_error("entry");
		parse_str_key(cse_entry, "name", (char *)out[i].entry_name,
			      sizeof(out[i].entry_name), &ret);
		if (ret < 0)
			return err_key_parse_error("entry");
		
		out[i].offset = parse_uint32_hex_key(cse_entry, "offset", -1, &ret);
		if (ret < 0)
			return err_key_parse_error("entry");
		
		out[i].length = parse_uint32_hex_key(cse_entry, "length", -1, &ret);
		if (ret < 0)
			return err_key_parse_error("entry");
		
		out[i].reserved = 0;
	}

	hdr->nb_entries = toml_array_nelem(cse_entry_array);

	DUMP("\ncse");
	DUMP_KEY("partition_name", "'%s'", hdr->partition_name);
	DUMP_KEY("header_version", "%d", hdr->header_version);
	DUMP_KEY("entry_version", "%d", hdr->entry_version);
	DUMP_KEY("nb_entries", "%d", hdr->nb_entries);
	for (i = 0; i < hdr->nb_entries; ++i) {
		DUMP_KEY("entry.name", "'%s'", out[i].entry_name);
		DUMP_KEY("entry.offset", "'0x%x", out[i].offset);
		DUMP_KEY("entry.length", "'0x%x", out[i].length);
	}

	/*
	 * values set in other places in code:
	 * - checksum
	 */

	return 0;
}

static int parse_mem_css_v1_8(const toml_table_t *toml, struct css_header_v1_8 *out)
{
	static const uint8_t hdr_id[4] = MAN_CSS_HDR_ID;
	toml_table_t *css;
	int ret;

	css = toml_table_in(toml, "css");
	if (!css)
		return err_key_not_found("css");

	/* non-configurable fields */
	memcpy(out->header_id, hdr_id, sizeof(out->header_id));
	out->padding = 0;
	out->reserved0 = 0;
	memset(out->reserved1, 0xff, sizeof(out->reserved1));

	/* configurable fields */
	out->header_type = parse_uint32_key(css, "header_type", MAN_CSS_MOD_TYPE, &ret);
	if (ret < 0)
		return ret;
	out->header_len = parse_uint32_key(css, "header_len", MAN_CSS_HDR_SIZE, &ret);
	if (ret < 0)
		return ret;
	out->header_version = parse_uint32_hex_key(css, "header_version", MAN_CSS_HDR_VERSION, &ret);
	if (ret < 0)
		return ret;
	out->module_vendor = parse_uint32_hex_key(css, "module_vendor", MAN_CSS_MOD_VENDOR, &ret);
	if (ret < 0)
		return ret;
	out->size = parse_uint32_key(css, "size", -1, &ret);
	if (ret < 0)
		return ret;
	out->svn = parse_uint32_key(css, "svn", 0, &ret);
	if (ret < 0)
		return ret;
	out->modulus_size = parse_uint32_key(css, "modulus_size", MAN_CSS_MOD_SIZE, &ret);
	if (ret < 0)
		return ret;
	out->exponent_size = parse_uint32_key(css, "exponent_size", MAN_CSS_EXP_SIZE, &ret);
	if (ret < 0)
		return ret;

	DUMP("\ncss");
	DUMP_KEY("header_type", "%d", out->header_type);
	DUMP_KEY("header_len", "%d", out->header_len);
	DUMP_KEY("header_version", "0x%x", out->header_version);
	DUMP_KEY("module_vendor", "0x%x", out->module_vendor);
	DUMP_KEY("size", "%d", out->size);
	DUMP_KEY("svn", "%d", out->svn);
	DUMP_KEY("modulus_size", "%d", out->modulus_size);
	DUMP_KEY("exponent_size", "%d", out->exponent_size);

	/*
	 * values set in other places in code:
	 * - date
	 * - version
	 * - modulus
	 * - exponent
	 * - signature
	 */

	return 0;
}

static int parse_mem_signed_pkg(const toml_table_t *toml, struct signed_pkg_info_ext *out)
{
	toml_array_t *bitmap_array;
	toml_array_t *module_array;
	toml_table_t *signed_pkg;
	toml_table_t *module;
	toml_raw_t raw;
	int64_t temp_i;
	int ret;
	int i;

	signed_pkg = toml_table_in(toml, "signed_pkg");
	if (!signed_pkg)
		return err_key_not_found("signed_pkg");

	out->ext_type = SIGN_PKG_EXT_TYPE;
	out->ext_len = sizeof(struct signed_pkg_info_ext);
	memset(out->reserved, 0, sizeof(out->reserved));

	parse_str_key(signed_pkg, "name", (char *)out->name, sizeof(out->name), &ret);
	if (ret < 0)
		return ret;

	out->vcn = parse_uint32_key(signed_pkg, "vcn", 0, &ret);
	if (ret < 0)
		return ret;

	/* bitmap array */
	bitmap_array = toml_array_in(signed_pkg, "bitmap");
	if (!bitmap_array)
		return err_key_not_found("bitmap");
	if (toml_array_kind(bitmap_array) != 'v' || toml_array_type(bitmap_array) != 'i' ||
	    toml_array_nelem(bitmap_array) > ARRAY_SIZE(out->bitmap))
		return err_key_parse_error("bitmap");

	for (i = 0; i < toml_array_nelem(bitmap_array); ++i) {
		raw = toml_raw_at(bitmap_array, i);
		if (!raw)
			return err_key_parse_error("bitmap");
		
		ret = toml_rtoi(raw, &temp_i);
		if (ret < 0 || temp_i < 0)
			return err_key_parse_error("bitmap");
		out->bitmap[i] = temp_i;
	}

	out->svn = parse_uint32_key(signed_pkg, "svn", 0, &ret);
	if (ret < 0)
		return ret;

	out->fw_type = parse_uint32_hex_key(signed_pkg, "fw_type", 0, &ret);
	if (ret < 0)
		return ret;

	out->fw_sub_type = parse_uint32_hex_key(signed_pkg, "fw_sub_type", 0, &ret);
	if (ret < 0)
		return ret;
	
	/* modules array */
	module_array = toml_array_in(signed_pkg, "module");
	if (!module_array)
		return err_key_not_found("module");
	if (toml_array_kind(module_array) != 't' ||
	    toml_array_nelem(module_array) != ARRAY_SIZE(out->module))
		return err_key_parse_error("module");

	for (i = 0; i < toml_array_nelem(module_array); ++i) {
		module = toml_table_at(module_array, i);
		if (!module)
			return err_key_parse_error("module");
		
		parse_str_key(module, "name", (char *)out->module[i].name,
			      sizeof(out->module[i].name), &ret);
		if (ret < 0)
			return err_key_parse_error("module");

		out->module[i].type = parse_uint32_hex_key(module, "type", -1, &ret);
		if (ret < 0)
			return err_key_parse_error("module");

		out->module[i].hash_algo = parse_uint32_hex_key(module, "hash_algo", -1, &ret);
		if (ret < 0)
			return err_key_parse_error("module");

		out->module[i].hash_size = parse_uint32_hex_key(module, "hash_size", -1, &ret);
		if (ret < 0)
			return err_key_parse_error("module");

		out->module[i].meta_size = parse_uint32_key(module, "meta_size", -1, &ret);
		if (ret < 0)
			return err_key_parse_error("module");
	}

	DUMP("\nsigned_pkg");
	DUMP_KEY("name", "'%s'", out->name);
	DUMP_KEY("vcn", "%d", out->vcn);
	DUMP_KEY("svn", "%d", out->svn);
	DUMP_KEY("fw_type", "%d", out->fw_type);
	DUMP_KEY("fw_sub_type", "%d", out->fw_sub_type);
	for (i = 0; i < ARRAY_SIZE(out->bitmap); ++i)
		DUMP_KEY("bitmap", "%d", out->bitmap[i]);
	for (i = 0; i < ARRAY_SIZE(out->module); ++i) {
		DUMP_KEY("meta.name", "'%s'", out->module[i].name);
		DUMP_KEY("meta.type", "'0x%x", out->module[i].type);
		DUMP_KEY("meta.hash_algo", "'0x%x", out->module[i].hash_algo);
		DUMP_KEY("meta.hash_size", "'0x%x", out->module[i].hash_size);
		DUMP_KEY("meta.meta_size", "'%d", out->module[i].meta_size);
	}

	/*
	 * values set in other places in code:
	 * - module.hash
	 */

	return 0;
}

static int parse_mem_partition_info_ext(const toml_table_t *toml, struct partition_info_ext *out)
{
	static const uint8_t module_reserved[3] = {0x00, 0xff, 0xff};
	toml_table_t *partition_info;
	toml_array_t *module_array;
	toml_table_t *module;
	int ret;
	int i;

	partition_info = toml_table_in(toml, "partition_info");
	if (!partition_info)
		return err_key_not_found("partition_info");

	/* non-configurable fields */
	out->ext_type = PART_INFO_EXT_TYPE;
	out->ext_len = sizeof(struct partition_info_ext);
	memset(out->reserved, 0xff, sizeof(out->reserved));

	/* configurable fields */
	parse_str_key(partition_info, "name", (char *)out->name, ARRAY_SIZE(out->name), &ret);
	if (ret < 0)
		return ret;

	out->vcn = parse_uint32_key(partition_info, "vcn", 0, &ret);
	if (ret < 0)
		return ret;

	out->part_version = parse_uint32_hex_key(partition_info, "part_version", 0, &ret);
	if (ret < 0)
		return ret;

	out->vcn = parse_uint32_hex_key(partition_info, "part_version", -1, &ret);
	if (ret < 0)
		return ret;

	out->vcn = parse_uint32_hex_key(partition_info, "fmt_version", 0, &ret);
	if (ret < 0)
		return ret;

	out->instance_id = parse_uint32_key(partition_info, "instance_id", -1, &ret);
	if (ret < 0)
		return ret;

	out->part_flags = parse_uint32_key(partition_info, "part_flags", 0, &ret);
	if (ret < 0)
		return ret;
	
	module_array = toml_array_in(partition_info, "module");
	if (!module_array || toml_array_kind(module_array) != 't' ||
	    toml_array_nelem(module_array) > ARRAY_SIZE(out->module))
		return err_key_parse_error("module");
	
	for (i = 0; i < toml_array_nelem(module_array); ++i) {
		module = toml_table_at(module_array, i);
		if (!module)
			return err_key_parse_error("module");
		parse_str_key(module, "name", (char *)out->module[i].name,
			      sizeof(out->module[i].name), &ret);
		if (ret < 0)
			return err_key_parse_error("module");
		out->module[i].meta_size = parse_uint32_key(module, "meta_size", -1, &ret);
		if (ret < 0)
			return err_key_parse_error("module");
		out->module[i].type = parse_uint32_hex_key(module, "type", -1, &ret);
		if (ret < 0)
			return err_key_parse_error("module");
		
		memcpy(out->module[i].reserved, module_reserved, sizeof(out->module[i].reserved));
	}

	DUMP("\npartition_info");
	DUMP_KEY("name", "'%s'", out->name);
	DUMP_KEY("part_version", "0x%x", out->part_version);
	DUMP_KEY("instance_id", "%d", out->instance_id);
	for (i = 0; i < ARRAY_SIZE(out->module); ++i) {
		DUMP_KEY("module.name", "'%s'", out->module[i].name);
		DUMP_KEY("module.meta_size", "0x%x", out->module[i].meta_size);	
		DUMP_KEY("module.type", "0x%x", out->module[i].type);	
	}

	/*
	 * values set in other places in code:
	 * - length
	 * - hash
	 * - module.hash
	 */

	return 0;
}

static int parse_mem_adsp_file_ext_v2_5(const toml_table_t *toml,
					struct sof_man_adsp_meta_file_ext_v2_5 *out)
{
	toml_table_t *adsp_file_ext;
	toml_array_t *comp_array;
	toml_table_t *comp;
	int ret;
	int i;

	adsp_file_ext = toml_table_in(toml, "adsp_file_ext");
	if (!adsp_file_ext)
		return err_key_not_found("adsp_file_ext");

	/* non configurable flieds */
	out->ext_type = 17; /* always 17 for ADSP extension */
	out->ext_len = sizeof(struct sof_man_adsp_meta_file_ext_v2_5);
	
	/* configurable fields */
	out->imr_type = parse_uint32_hex_key(adsp_file_ext, "imr_type", 0, &ret);
	if (ret < 0)
		return ret;

	/* parse comp array */
	comp_array = toml_array_in(adsp_file_ext, "comp");
	if (!comp_array || toml_array_nelem(comp_array) != 1 || toml_array_kind(comp_array) != 't')
		return err_key_not_found("comp");

	for(i = 0; i < toml_array_nelem(comp_array); ++i){
		comp = toml_table_at(comp_array, i);
		if (!comp)
			return err_key_parse_error("comp");

		out->comp_desc[i].version = parse_uint32_key(comp, "version", -1, &ret);
		if (ret < 0)
			return err_key_parse_error("comp");

		out->comp_desc[i].base_offset = parse_uint32_hex_key(comp, "base_offset", -1,
									  &ret);
		if (ret < 0)
			return err_key_parse_error("comp");
	}

	/*
	 * values set in other places in code:
	 * - imr_type
	 * - comp.limit_offset
	 */

	DUMP("\nadsp_file_ext");
	DUMP_KEY("imr_type", "0x%x", out->imr_type);
	for (i = 0; i < ARRAY_SIZE(out->comp_desc); ++i) {
		DUMP_KEY("comp.version", "0x%x", out->comp_desc[i].version);
		DUMP_KEY("comp.base_offset", "0x%x", out->comp_desc[i].base_offset);	
	}

	return 0;
}

static int parse_mem_fw_desc(const toml_table_t *toml, struct sof_man_fw_desc *out)
{
	static const uint8_t header_id[4] = SOF_MAN_FW_HDR_ID;
	toml_table_t *header;
	toml_table_t *desc;
	int ret;

	desc = toml_table_in(toml, "fw_desc");
	if (!desc)
		return err_key_not_found("fw_desc");

	header = toml_table_in(desc, "header");
	if (!header)
		return err_key_not_found("header");

	/* non configurable flieds */
	memcpy(&out->header.header_id, header_id, sizeof(header_id));
	out->header.header_len = sizeof(struct sof_man_fw_header);

	/* configurable fields */
	parse_str_key(header, "name", (char *)out->header.name, SOF_MAN_FW_HDR_FW_NAME_LEN, &ret);
	if (ret < 0)
		return err_key_parse_error("header");

	out->header.preload_page_count = parse_uint32_key(header, "preload_page_count", -1, &ret);
	if (ret < 0)
		return err_key_parse_error("header");

	out->header.fw_image_flags = parse_uint32_hex_key(header, "fw_image_flags", -1, &ret);
	if (ret < 0)
		return err_key_parse_error("header");

	out->header.feature_mask = parse_uint32_hex_key(header, "feature_mask", 0, &ret);
	if (ret < 0)
		return err_key_parse_error("header");

	out->header.hw_buf_base_addr = parse_uint32_key(header, "hw_buf_base_addr", 0, &ret);
	if (ret < 0)
		return err_key_parse_error("header");

	out->header.hw_buf_length = parse_uint32_key(header, "hw_buf_length", 0, &ret);
	if (ret < 0)
		return err_key_parse_error("header");

	/*
	 * values set in other places in code:
	 * - major_version
	 * - minor_version
	 * - build_version
	 * - num_module_entries
	 */

	DUMP("\nfw_desc.header");
	DUMP_KEY("header_id", "'%c%c%c%c'", out->header.header_id[0], out->header.header_id[1],
		  out->header.header_id[2], out->header.header_id[3]);
	DUMP_KEY("name", "'%s'", out->header.name);
	DUMP_KEY("preload_page_count", "%d", out->header.preload_page_count);
	DUMP_KEY("fw_image_flags", "0x%x", out->header.fw_image_flags);
	DUMP_KEY("feature_mask", "0x%x", out->header.feature_mask);
	DUMP_KEY("hw_buf_base_addr", "0x%x", out->header.hw_buf_base_addr);
	DUMP_KEY("hw_buf_length", "0x%x", out->header.hw_buf_length);
	DUMP_KEY("load_offset", "0x%x", out->header.load_offset);

	return 0;

}

static int parse_adsp_config_v2_5(const toml_table_t *toml, struct adsp *out)
{
	int ret;

	out->man_v2_5 = malloc(sizeof(struct fw_image_manifest_v2_5));
	if (!out->man_v2_5)
		return err_malloc("man_v2_5");

	ret = parse_mem_cse(toml, &out->man_v2_5->cse_partition_dir_header, out->man_v2_5->cse_partition_dir_entry);
	if (ret < 0)
		return err_key_parse_error("cse");

	ret = parse_mem_css_v1_8(toml, &out->man_v2_5->css);
	if (ret < 0)
		return err_key_parse_error("css");

	ret = parse_mem_signed_pkg(toml, &out->man_v2_5->signed_pkg);
	if (ret < 0)
		return err_key_parse_error("signed_pkg");

	ret = parse_mem_partition_info_ext(toml, &out->man_v2_5->partition_info);
	if (ret < 0)
		return err_key_parse_error("partition_info_ext");

	ret = parse_mem_adsp_file_ext_v2_5(toml, &out->man_v2_5->adsp_file_ext);
	if (ret < 0)
		return err_key_parse_error("adsp_file_ext");

	ret = parse_mem_fw_desc(toml, &out->man_v2_5->desc);
	if (ret < 0)
		return err_key_parse_error("fw_desc");

	return 0;
}

static int parse_adsp_config_fd(FILE *fd, struct adsp *out)
{
	int64_t css_version[2];
	toml_table_t* toml;
	toml_array_t* arr;
	toml_raw_t raw;
	char errbuf[256];
	int ret;
	int i;

	toml = toml_parse_file(fd, errbuf, ARRAY_SIZE(errbuf));
	if (!toml)
		return log_err(-EINVAL, "error: toml file parsing\n");

	/* check "version" key */
	arr = toml_array_in(toml, "version");
	if (!arr || toml_array_type(arr) != 'i'  || toml_array_nelem(arr) != 2 ||
	    toml_array_kind(arr) != 'v') {
		ret = log_err(-EINVAL, "error: toml parse key 'version' failed\n");
		goto error;
	}

	for(i = 0; i < ARRAY_SIZE(css_version); ++i){
		raw = toml_raw_at(arr, i);
		if (ret < 0)
			ret = log_err(-EINVAL, "error: toml fetching key 'version' failed\n");
		ret = toml_rtoi(raw, &css_version[i]);
		if (ret < 0)
			ret = log_err(-EINVAL, "error: toml reading key 'version' failed\n");
	}

	if (check_config_version(2, 5, css_version)) {
		ret = parse_adsp_config_v2_5(toml, out);
	} else {
		ret = log_err(-EINVAL, "error: Unsupported config version %d.%d\n", css_version[0], css_version[1]);
		goto error;
	}

error:
	toml_free(toml);
	return ret;
}

int parse_adsp_config(const char* file, struct adsp *out)
{
	FILE *fd;
	int ret;

	fd = fopen(file, "r");
	if (!fd)
		return log_err(-EIO, "error: can't open '%s' file\n", file);
	ret = parse_adsp_config_fd(fd, out);
	fclose(fd);
	return ret;
}

void adsp_free(struct adsp *adsp)
{
	if (!adsp)
		return;
	
	if (adsp->man_v2_5)
		free(adsp->man_v2_5);

	free(adsp);
}