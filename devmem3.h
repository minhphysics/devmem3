#ifndef DEVMEM3_H__
#define DEVMEM3_H__

#include <stdint.h>

#define MAX_LABEL_LEN 20

struct mapping {
	unsigned int paddr;
	void *vaddr;
};

struct rw_data {
	unsigned int offset;
	unsigned int data;
	bool write;
};

struct label_data {
	unsigned int offset;
	char label[MAX_LABEL_LEN];
	size_t size;
};

struct ignored_data {
	unsigned int offset;
};

struct devmem {
	struct mapping *maps;
	struct rw_data *rw_data;
	struct label_data *lb_data;
	struct ignored_data *ig_data;
	int num_map;
	int num_rw;
	int num_lb;
	int num_ig;
	unsigned int base;
	unsigned start_offset;
	int num_reg;
	bool dump;
};

void add_mapping(struct devmem *dev, unsigned int address);
void add_rw_data(struct devmem *dev, unsigned int offset, unsigned int dat, bool is_write);
void add_label_data(struct devmem *dev, unsigned int offset, char *label, size_t size);
void add_ignored_data(struct devmem *dev, unsigned int offset);
struct mapping *get_mapping(struct devmem *dev, unsigned int address);
bool is_ignored(struct devmem *dev, unsigned int offset);
int read_data(struct devmem *dev, unsigned int paddr, unsigned int *data);
void write_data(struct devmem *dev, unsigned int paddr, unsigned int data);
void dump_range(struct devmem *dev);
void dump_label_reg(struct devmem *dev);
void dump_rw_reg(struct devmem *dev);

#endif	//DEVMEM3_H
