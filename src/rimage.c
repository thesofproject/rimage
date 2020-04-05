// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright(c) 2015 Intel Corporation. All rights reserved.

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "rimage.h"
#include "manifest.h"

static const struct adsp *machine[] = {
	&machine_byt,
	&machine_cht,
	&machine_bsw,
	&machine_hsw,
	&machine_bdw,
	&machine_apl,
	&machine_cnl,
	&machine_icl,
	&machine_jsl,
	&machine_tgl,
	&machine_sue,
	&machine_kbl,
	&machine_skl,
	&machine_imx8,
	&machine_imx8x,
	&machine_imx8m,
};

static void usage(char *name)
{
	fprintf(stdout, "%s:\t -m machine -o outfile -k [key] ELF files\n",
		name);
	fprintf(stdout, "\t -v enable verbose output\n");
	fprintf(stdout, "\t -r enable relocatable ELF files\n");
	fprintf(stdout, "\t -s MEU signing offset\n");
	fprintf(stdout, "\t -i set IMR type\n");
	fprintf(stdout, "\t -x set xcc module offset\n");
	fprintf(stdout, "\t -f firmware version = x.y\n");
	fprintf(stdout, "\t -b build version\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	struct image image;
	const char *mach = NULL;
	int opt, ret, i, elf_argc = 0;
	int imr_type = MAN_DEFAULT_IMR_TYPE;

	memset(&image, 0, sizeof(image));

	image.xcc_mod_offset = DEFAULT_XCC_MOD_OFFSET;

	while ((opt = getopt(argc, argv, "ho:m:va:s:k:l:ri:x:f:b:")) != -1) {
		switch (opt) {
		case 'o':
			image.out_file = optarg;
			break;
		case 'm':
			mach = optarg;
			break;
		case 'v':
			image.verbose = 1;
			break;
		case 's':
			image.meu_offset = atoi(optarg);
			break;
		case 'a':
			image.abi = atoi(optarg);
			break;
		case 'k':
			image.key_name = optarg;
			break;
		case 'r':
			image.reloc = 1;
			break;
		case 'i':
			imr_type = atoi(optarg);
			break;
		case 'x':
			image.xcc_mod_offset = atoi(optarg);
			break;
		case 'f':
			image.fw_ver_string = optarg;
			break;
		case 'b':
			image.fw_ver_build_string = optarg;
			break;
		case 'h':
			usage(argv[0]);
			break;
		default:
			break;
		}
	}

	elf_argc = optind;

	/* make sure we have an outfile and machine */
	if (!image.out_file || !mach)
		usage(argv[0]);

	/* requires private key */
	if (!image.key_name) {
		fprintf(stderr, "error: requires private key\n");
		return -EINVAL;
	}

	/* firmware version and build id */
	if (image.fw_ver_string) {
		ret = sscanf(image.fw_ver_string, "%hu.%hu",
			     &image.fw_ver_major,
			     &image.fw_ver_minor);

		if (ret != 2) {
			fprintf(stderr,
				"error: cannot parse firmware version\n");
			return -EINVAL;
		}
	}

	if (image.fw_ver_build_string) {
		ret = sscanf(image.fw_ver_build_string, "%hu",
			     &image.fw_ver_build);

		if (ret != 1) {
			fprintf(stderr,
				"error: cannot parse build version\n");
			return -EINVAL;
		}
	}

	/* find machine */
	for (i = 0; i < ARRAY_SIZE(machine); i++) {
		if (!strcmp(mach, machine[i]->name)) {
			image.adsp = machine[i];
			goto found;
		}
	}
	fprintf(stderr, "error: machine %s not found\n", mach);
	fprintf(stderr, "error: available machines ");
	for (i = 0; i < ARRAY_SIZE(machine); i++)
		fprintf(stderr, "%s, ", machine[i]->name);
	fprintf(stderr, "\n");

	return -EINVAL;

found:

	/* set IMR Type in found machine definition */
	if (image.adsp->man_v1_8)
		image.adsp->man_v1_8->adsp_file_ext.imr_type = imr_type;

	if (image.adsp->man_v2_5)
		image.adsp->man_v2_5->adsp_file_ext.imr_type = imr_type;

	/* parse input ELF files */
	image.num_modules = argc - elf_argc;
	for (i = elf_argc; i < argc; i++) {
		fprintf(stdout, "\nModule Reading %s\n", argv[i]);
		ret = elf_parse_module(&image, i - elf_argc, argv[i]);
		if (ret < 0)
			goto out;
	}

	/* validate all modules */
	ret = elf_validate_modules(&image);
	if (ret < 0)
		goto out;

	/* open outfile for writing */
	unlink(image.out_file);
	image.out_fd = fopen(image.out_file, "wb");
	if (!image.out_fd) {
		fprintf(stderr, "error: unable to open %s for writing %d\n",
			image.out_file, errno);
		ret = -EINVAL;
		goto out;
	}

	/* process and write output */
	if (image.meu_offset)
		ret = image.adsp->write_firmware_meu(&image);
	else
		ret = image.adsp->write_firmware(&image);

out:
	/* close files */
	if (image.out_fd)
		fclose(image.out_fd);

	return ret;
}
