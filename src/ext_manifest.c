// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2020 Intel Corporation. All rights reserved.
//
// Author: Karol Trzcinski <karolx.trzcinski@linux.intel.com>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "kernel/ext_manifest_gen.h"
#include "kernel/ext_manifest.h"
#include "common.h"
#include "rimage.h"

const struct ext_man_header ext_man_template = {
	.magic = EXT_MAN_MAGIC_NUMBER,
	.header_version = EXT_MAN_VERSION,
	.header_size = sizeof(struct ext_man_header),
	.full_size = 0,	/* runtime variable */
};

static int ext_man_open_file(struct image *image)
{
	/* open extended manifest outfile for writing */
	sprintf(image->out_ext_man_file, "%s.xman", image->out_file);
	unlink(image->out_ext_man_file);

	image->out_ext_man_fd = fopen(image->out_ext_man_file, "wb");
	if (!image->out_ext_man_fd) {
		fprintf(stderr, "error: unable to open %s for writing %d\n",
			image->out_ext_man_file, errno);
		return errno;
	}

	return 0;
}

static const struct module *ext_man_find_module(const struct image *image)
{
	const struct module *module;
	int i;

	/* when there is more than one module, then first one is bootloader */
	for (i = image->num_modules == 1 ? 0 : 1; i < image->num_modules; i++) {
		module = &image->module[i];
		if (elf_find_section(module, EXT_MAN_DATA_SECTION) >= 0)
			return module;
	}

	return NULL;
}

static int ext_man_validate(uint32_t section_size, const void *section_data)
{
	uint8_t *sbuf = (uint8_t *)section_data;
	struct ext_man_elem_header head;
	uint32_t offset = 0;

	/* copy each head to local struct to omit memory align issues */
	while (offset < section_size) {
		memcpy(&head, &sbuf[offset], sizeof(head));
		fprintf(stdout, "Extended manifest found module, type: 0x%04X size: 0x%04X (%4d) offset: 0x%04X\n",
			head.type, head.elem_size, head.elem_size, offset);
		if (head.elem_size == 0 || head.elem_size % EXT_MAN_ALIGN) {
			fprintf(stderr,
				"error: invalid extended manifest element size\n");
			return -EINVAL;
		}
		offset += head.elem_size;
	}

	/* sum of packets size != section size */
	if (offset != section_size) {
		fprintf(stderr,
			"error: fw_metadata section is inconsistent, section size: 0x%04X != 0x%04X sum of packets size\n",
			section_size, offset);
		return -EINVAL;
	} else {
		return 0;
	}
}

/*
 * Insert `section_name` content after `elem_type` header.
 * Save result in new buffer, then replace `meta_section_data`.
 * Return `section_name` size or error code.
 */
static int ext_man_update_element_with_list(const struct module *module,
					    int32_t *metadata_size,
					    uint8_t **metadata_buff,
					    enum ext_man_elem_type elem_type,
					    const char *section_name)
{
	struct ext_man_elem_header* head = NULL;
	uint8_t *meta_buff = *metadata_buff;
	uint8_t *sec_buffer = NULL;
	const Elf32_Shdr *section;
	int32_t extra_elem_size;
	int32_t extra_mem_size;
	int32_t split_offset;
	int32_t padding_size;
	uint32_t offset = 0;
	uint8_t *temp_buff;
	int ret;

	/* find `elem_type` in meta_section */
	while (offset < *metadata_size) {
		head = (struct ext_man_elem_header*)&meta_buff[offset];
		if (head->type == elem_type || !head->elem_size)
			break;
		offset += head->elem_size;
	}

	if (!head || head->type != elem_type) {
		fprintf(stdout,
			"Extended manifest element %d not found\n", elem_type);
		return -EINVAL;
	}

	/* read section with content of the list */
	ret = elf_read_section(module, section_name, &section,
			       (void **)&sec_buffer);
	if (ret < 0) {
		fprintf(stderr,
			"error: failed to read %s section content, code %d\n",
			section_name, ret);
		return ret;
	}

	split_offset = offset + head->elem_size;
	extra_mem_size =
		ALIGN_UP(head->elem_size + section->size, EXT_MAN_ALIGN) -
		ALIGN_UP(head->elem_size, EXT_MAN_ALIGN);
	extra_elem_size =
		ALIGN_UP(head->elem_size + section->size, EXT_MAN_ALIGN) -
		head->elem_size;
	padding_size =
		ALIGN_UP(head->elem_size, EXT_MAN_ALIGN) - head->elem_size;

	temp_buff = malloc(*metadata_size + extra_mem_size);
	if (!temp_buff) {
		free(sec_buffer);
		return -ENOMEM;
	}

	/* 
	 * update element size and insert the list after element header,
	 */
	head->elem_size += extra_elem_size;
	memcpy(&temp_buff[0], meta_buff, split_offset);
	memcpy(&temp_buff[split_offset], sec_buffer, section->size);
	memcpy(&temp_buff[offset + head->elem_size],
	       &meta_buff[split_offset + padding_size],
	       max(0, *metadata_size - split_offset - padding_size));

	free(*metadata_buff);
	*metadata_buff = temp_buff;
	*metadata_size = ALIGN_UP(*metadata_size + extra_mem_size,
				  EXT_MAN_ALIGN);

	return 0;
}

static int ext_man_build(const struct module *module,
			 struct ext_man_header **dst_buff)
{
	struct ext_man_header ext_man;
	const Elf32_Shdr *section;
	uint8_t *buffer = NULL;
	uint8_t *sec_buffer = NULL;
	int32_t sec_buffer_size;
	int ret = 0;

	sec_buffer_size = elf_read_section(module, EXT_MAN_DATA_SECTION,
					   &section, (void **)&sec_buffer);
	if (sec_buffer_size < 0) {
		fprintf(stderr,
			"error: failed to read %s section content, code %d\n",
			EXT_MAN_DATA_SECTION, ret);
		return sec_buffer_size;
	}

	ret = ext_man_update_element_with_list(module, &sec_buffer_size,
					       &sec_buffer,
					       EXT_MAN_ELEM_UUID_DICT,
					       EXT_MAN_UUID_DICT_SECTION);
	if (ret < 0) {
		fprintf(stderr,
			"error: failed to update extended manifest element with %s section content, code %d\n",
			EXT_MAN_UUID_DICT_SECTION, ret);
		goto out;
	}

	/* fill ext_man struct, size aligned to 4 to avoid unaligned accesses */
	memcpy(&ext_man, &ext_man_template, sizeof(struct ext_man_header));
	ext_man.full_size = ext_man.header_size;
	ext_man.full_size += sec_buffer_size;
	if (ext_man.full_size % 4) {
		fprintf(stderr,
			"error: extended manifest size must be aligned to 4\n");
		ret = -EINVAL;
		goto out;
	}

	/* alloc buffer for ext_man */
	buffer = calloc(1, ext_man.full_size);
	if (!buffer) {
		ret = -ENOMEM;
		goto out;
	}

	/* fill buffer with ext_man and section content */
	memcpy(buffer, &ext_man, ext_man.header_size);
	memcpy(&buffer[ext_man.header_size], sec_buffer, sec_buffer_size);

	*dst_buff = (struct ext_man_header *)buffer;

out:
	if (!sec_buffer)
		free(sec_buffer);
	return ret;
}

int ext_man_write(struct image *image)
{
	const struct module *module;
	struct ext_man_header *ext_man = NULL;
	int count;
	int ret;

	ret = ext_man_open_file(image);
	if (ret)
		goto out;

	module = ext_man_find_module(image);
	if (!module) {
		ret = -ECANCELED;
		goto out;
	}

	ret = ext_man_build(module, &ext_man);
	if (ret)
		goto out;

	/* validate metadata section */
	ret = ext_man_validate(ext_man->full_size - ext_man->header_size,
			       (char *)ext_man + ext_man->header_size);
	if (ret) {
		ret = -errno;
		goto out;
	}

	/* write extended metadata to file */
	count = fwrite(ext_man, 1, ext_man->full_size, image->out_ext_man_fd);

	if (count != ext_man->full_size) {
		fprintf(stderr,
			"error: can't write extended manifest to file %d\n",
			-errno);
		ret = -errno;
		goto out;
	}

	fprintf(stdout, "Extended manifest saved to file %s size 0x%04X (%d) bytes\n\n",
		image->out_ext_man_file, ext_man->full_size,
		ext_man->full_size);

out:
	if (ext_man)
		free(ext_man);
	if (image->out_ext_man_fd)
		fclose(image->out_ext_man_fd);
	return ret;
}
