all: devmem3

devmem3: devmem3.c
	$(CC) -Wall -O -o $@ $^

.PHONY: clean

clean:
	rm -f devmem3
