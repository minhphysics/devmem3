#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/mman.h>

#include "devmem3.h"

#define printerr(fmt, ...)               \
    do                                   \
{                                        \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    fflush(stderr);                      \
} while (0)

#define VER_STR "devmem3 version 1.0.0"
#define JUST_GAP "-------------------------------------------\n"
unsigned int page_size;

/* Usage */
static void usage(const char *cmd)
{
    fprintf(stderr, "\nUsage:\t%s [-b <base address>] <cmd> [<cmd> ...]\n"
	    "\t-b <base address>: base address to add to offset specified in commands\n\n"
	    "\tcommands:\n"
	    "\td <start offset>: dump ranges of words\n"
	    "\tn <num regs>: number of words to be dumped\n"
	    "\tl <offset> <label>: label for offset (optional)\n"
	    "\ti <offset>: ignored offset (optional)\n\n"
	    "\tr <offset>: read\n"
	    "\tw <offset> <data>: write and read back\n\n"
	    "\t--version | -v : print version\n"
	    "\n",
	    cmd);
}
/* Add data to read or write */
void add_rw_data(struct devmem *dev, unsigned int offset, unsigned int dat, bool is_write)
{
	struct rw_data *data;
	int i;

	/* Check dupilcate offset */
	for (i = 0; i < dev->num_rw; i++) {
		data = &dev->rw_data[i];
		if (data->offset == offset && data->write == is_write) {
			data->data = dat;
			return;
		}
	}

	dev->num_rw++;
	dev->rw_data = realloc(dev->rw_data, sizeof(*(dev->rw_data)) * dev->num_rw);

	data = &dev->rw_data[dev->num_rw - 1];
	data->offset = offset;
	data->write = is_write;
	if (is_write)
		data->data = dat;
	else
		data->data = 0;
}

/* Add data with label */
void add_label_data(struct devmem *dev, unsigned int offset, char *label, size_t size)
{
	struct label_data *data;
	int i;

	/* Check duplicate offset */
	for (i = 0; i < dev->num_lb; i++) {
		data = &dev->lb_data[i];
		if (data->offset == offset) {
			strncpy(data->label, label, size);
			data->size = size;
			return;
		}
	}

	dev->num_lb++;
	dev->lb_data = realloc(dev->lb_data, sizeof(*(dev->lb_data)) * dev->num_lb);

	data = &dev->lb_data[dev->num_lb - 1];
	data->offset = offset;
	data->size = size;
	strncpy(data->label, label, size);
}

void add_ignored_data(struct devmem *dev, unsigned int offset)
{
	struct ignored_data *data;
	int i;

	/* Check duplicate offset */
	for (i = 0; i < dev->num_ig; i++) {
		data = &dev->ig_data[i];
		if (data->offset == offset)
			return;
	}

	dev->num_ig++;
	dev->ig_data = realloc(dev->ig_data, sizeof(*(dev->ig_data)) * dev->num_ig);
	data = &dev->ig_data[dev->num_ig - 1];
	data->offset = offset;
}

/* Add map with length of default page_size if the address is not in existing mappings*/
void add_mapping(struct devmem *dev, unsigned int address)
{
	struct mapping *map;
	int i;

	if (page_size == 0)
		page_size = (unsigned int)sysconf(_SC_PAGESIZE);

	for (i = 0; i < dev->num_map; i++) {
		map = &dev->maps[i];
		if (address >= map->paddr && address < (map->paddr + page_size))
			return;
	}

	dev->num_map++;
	dev->maps = realloc(dev->maps, sizeof(*(dev->maps)) * dev->num_map);
	map = &dev->maps[dev->num_map - 1];
	map->paddr = (address & ~(page_size - 1));
	map->vaddr = NULL;
}

/* Get struct mapping which include the input address */
struct mapping *get_mapping(struct devmem *dev, unsigned int address)
{
	struct mapping *map;
	int i;

	for (i = 0; i < dev->num_map; i++) {
		map = &dev->maps[i];
		if (address >= map->paddr && address < (map->paddr + page_size)) {
			return map;
		}
	}

	return NULL;
}

/* Check if the offset should be ignored */
bool is_ignored(struct devmem *dev, unsigned int offset)
{
	struct ignored_data *data;
	int i;

	for (i = 0; i < dev->num_ig; i++) {
		data = &dev->ig_data[i];
		if (data->offset == offset)
			return true;
	}

	return false;
}

/* Check if number is valid */
bool is_valid_num(const char *str, unsigned int *value)
{
	char *endp;
	unsigned int val = strtoull(str, &endp, 0);

	if (endp == str)
		return false;
	if (*endp != 0)
		return false;
	if (value)
		*value = val;

	return true;
}

/* Check if any invalid params and add mapping for addresses */
int parse_params(struct devmem *dev, int argc, char **argv)
{
	unsigned int base_addr;
	unsigned int address;
	unsigned int offset;
	unsigned int data;
	char cmd;
	int i;

	for (i = 0; i < argc; i++) {
		int j = 0;

		cmd = argv[i][j++];
		switch (cmd) {
			case 'd':
				i++;
				if (i >= argc) {
					printerr("missing offset after -d\n");
					goto err;
				}

				if (!is_valid_num(argv[i], &offset)) {
					printerr("invalid offset\n");
					goto err;
				}

				dev->dump = true;
				dev->start_offset = offset;

				break;
			case 'n':
				i++;
				if (i >= argc) {
					printerr("missing offset after -r\n");
					goto err;
				}

				if (!is_valid_num(argv[i], &offset)) {
					printerr("invalid offset\n");
					goto err;
				}

				dev->num_reg = offset;
				break;
			case 'r':
				i++;
				if (i >= argc) {
					printerr("missing offset after -r\n");
					goto err;
				}

				if (!is_valid_num(argv[i], &offset)) {
					printerr("invalid offset\n");
					goto err;
				}

				add_mapping(dev, dev->base + offset);
				add_rw_data(dev, offset, 0, false);
				break;
			case 'w':
				i++;
				if (i >= argc) {
					printerr("missing offset after -w\n");
					goto err;
				}

				if (!is_valid_num(argv[i], &offset)) {
					printerr("invalid offset\n");
					goto err;
				}

				i++;
				if (i >= argc) {
					printerr("missing data after -w\n");
					goto err;
				}

				if (!is_valid_num(argv[i], &data)) {
					printerr("invalid data\n");
					goto err;
				}
				add_mapping(dev, dev->base + offset);
				add_rw_data(dev, offset, data, true);
				break;
			case 'l':
				i++;
				if (i >= argc) {
					printerr("missing offset after -l\n");
					goto err;
				}

				if (!is_valid_num(argv[i], &offset)) {
					printerr("invalid offset\n");
					goto err;
				}
				i++;
				if (i >= argc) {
					printerr("missing label\n");
					goto err;
				}

				add_mapping(dev, dev->base + offset);
				add_label_data(dev, offset, argv[i], sizeof(argv[i]));
				break;
			case 'i':
				i++;
				if (i >= argc) {
					printerr("missing offset after -i\n");
					goto err;
				}

				if (!is_valid_num(argv[i], &offset)) {
					printerr("invalid offset\n");
					goto err;
				}

				add_ignored_data(dev, offset);
				break;
		}
	}

	base_addr = dev->base + dev->start_offset;
	address = base_addr;

	while (address < base_addr + dev->num_reg * 4 + page_size) {//4 bytes sliding for 32bit register
		add_mapping(dev, address);
		address += page_size;
	}

	return 0;
err:
	return -1;
}

/* Read data */
int read_data(struct devmem *dev, unsigned int paddr, unsigned int *data)
{
	struct mapping *map;
	void *vaddr;

	map = get_mapping(dev, paddr);
	if (map == NULL || map->vaddr == NULL) {
		printerr("reading at address 0x%x failed\n", paddr);
		return -1;
	}

	vaddr = map->vaddr + (paddr - map->paddr);
	*data = *(volatile uint32_t *)vaddr; //currently only support read dword (32 bit)
	return 0;
}

/* Write data */
void write_data(struct devmem *dev, unsigned int paddr, unsigned int data)
{
	struct mapping *map;
	void *vaddr;

	map = get_mapping(dev, paddr);
	if (map == NULL || map->vaddr == NULL) {
		printerr("writing at address 0x%x failed\n", paddr);
		return;
	}
	vaddr = map->vaddr + (paddr - map->paddr);
	*(volatile uint32_t *)vaddr = data; //currently only support write dword (32 bit)
}

/* Dump registers */
void dump_range(struct devmem *dev)
{
	unsigned int base = (dev->base + dev->start_offset) & ~0x0fUL;
	unsigned int paddr = dev->base + dev->start_offset;
	unsigned int max_addr = dev->base + dev->start_offset + dev->num_reg * 4;
	unsigned int data;
	unsigned int offset = dev->start_offset;
	int col_num = 4;
	int col, row = 0;
	int ret;

	if (!dev->dump)
		return;

	fprintf(stdout, "\t\t00\t\t04\t\t08\t\t0C\n\n");
	while (paddr < max_addr) {
		fprintf(stdout, "0x%08x \t", base + row * 0x10);
		for (col = 0; col < col_num; col++) {
			if (row == 0 && (base + col * 4) < paddr) {
				fprintf(stdout, "\t\t");
				continue;
			}

			if (is_ignored(dev, offset))
				fprintf(stdout, "--\t\t");
			else {
				/* read data */
				ret = read_data(dev, paddr, &data);
				if (ret)
					fprintf(stdout, "??\t");
				else
					fprintf(stdout, "%08x\t", data);
			}

			paddr += 4; //Increment address
			offset += 4;
			if (paddr >= max_addr)
				break;
			if (col == (col_num - 1))
				fprintf(stdout, "\n\n");
		}
		row++;
	}
	fprintf(stdout, "\n");
}

/* Dump register with label */
void dump_label_reg(struct devmem *dev)
{
	struct label_data *data;
	unsigned int base_addr = dev->base;
	unsigned int paddr;
	unsigned int val;
	int i, ret;

	if (dev->lb_data == NULL)
		return;
	fprintf(stdout, "Label\t\tAddress\t\tValue\n\n");
	for (i = 0; i < dev->num_lb; i++) {
		data = &dev->lb_data[i];

		fprintf(stdout, "%.*s\t", (int)data->size, data->label);
		if (is_ignored(dev, data->offset))
			fprintf(stdout, "--\n");
		else {
			paddr = base_addr + data->offset;

			ret = read_data(dev, paddr, &val);
			if (ret)
				fprintf(stdout, "0x%08x\t??\n", paddr);
			else
				fprintf(stdout, "0x%08x\t%08x\n", paddr, val);
		}
	}
}

/* Read and write-readback register */
void dump_rw_reg(struct devmem *dev)
{
	struct rw_data *data;
	unsigned int base_addr = dev->base;
	unsigned int paddr;
	unsigned int val;
	int i, ret;

	if (dev->rw_data == NULL)
		return;

	for (i = 0; i < dev->num_rw; i++) {
		data = &dev->rw_data[i];
		paddr = base_addr + data->offset;

		if (data->write) {
			write_data(dev, paddr, data->data);
			ret = read_data(dev, paddr, &val);
			if (!ret)
				fprintf(stdout, "0x%08x: written 0x%08x; read back 0x%08x\n",
					paddr, data->data, val);
		} else {
			ret = read_data(dev, paddr, &val);
			if (!ret)
				fprintf(stdout, "0x%08x: read 0x%08x\n", paddr, val);
		}
	}
}

int main(int argc, char **argv)
{
	struct devmem dev;
	int fd = 0, i, ch;
	char *endptr;
	/* Intitialize data */
	dev.base = 0;
	dev.start_offset = 0;
	dev.num_map = 0;
	dev.num_rw = 0;
	dev.num_lb = 0;
	dev.num_ig = 0;
	dev.num_reg = 0;
	dev.maps = NULL;
	dev.rw_data = NULL;
	dev.lb_data = NULL;
	dev.ig_data = NULL;
	dev.dump = false;

	while ((ch = getopt(argc, argv, "b:hv")) != -1) {
		switch (ch) {
		case 'b':
			dev.base = strtoull(optarg, &endptr, 0);
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		case 'v':
			fprintf(stdout, VER_STR "\n");
			return 0;
		default:
			if (0 == strncmp(argv[optind], "--vers", 6)){
				fprintf(stdout, VER_STR "\n");
				return 0;
			}

			if (0 == strcmp(argv[optind], "--help")){
				usage(argv[0]);
				return 0;
			}
		}
	}

	if (dev.base == 0) {
		printerr("no base address\n");
		usage(argv[0]);
		goto err;
	}

	if (parse_params(&dev, argc - optind, argv + optind)) {
		printerr("invalid option\n");
		goto err;
	}

	fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd < 0) {
		printerr("failed to open /dev/mem\n");
		goto err;
	}

	for (i = 0; i < dev.num_map; i++) {
		struct mapping *map;

		map = &dev.maps[i];
		map->vaddr = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
				  MAP_SHARED, fd, map->paddr);

		if (map->vaddr == MAP_FAILED) {
			printerr("failed to mmap /dev/mem\n");
			close(fd);
			goto err;
		}
	}

	dump_range(&dev);

	dump_label_reg(&dev);

	dump_rw_reg(&dev);

	close(fd);
err:
	for (i = 0; i < dev.num_map; i++)
		munmap(dev.maps[i].vaddr, page_size);

	free(dev.maps);
	free(dev.rw_data);
	free(dev.lb_data);
	free(dev.ig_data);

	return 0;
}

