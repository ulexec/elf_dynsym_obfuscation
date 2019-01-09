#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <elf.h>

#define PAGE_SIZE 		4096
#define	PAGE_ALIGN(k) 		(((k)+((PAGE_SIZE)-1))&(~((PAGE_SIZE)-1)))
#define PIC_RESOLVE_ADDR(target) (get_rip() - ((char *)&get_rip_label - (char *)target))

uint32_t dynstr_buf[8192] __attribute__((section(".data"), aligned(8))) =
    { [0 ... 8191] = 0};
unsigned long dynstr_size __attribute__((section(".data"))) = {0};
extern unsigned long get_rip_label;

struct link_map {
	Elf64_Addr l_addr;
	char * l_name;
	Elf64_Dyn *l_ld;
	struct link_map *l_next, *l_prev;
};

uint32_t elf_hash(const unsigned char *name) 
{
	uint32_t h = 0, g;
	while (*name) {
		h = (h << 4) + *name++;
		g = h & 0xf0000000;
		if (g)
			h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

uint64_t lookup(uint32_t name_hash, uint32_t *hashtab, Elf64_Sym *symtab, uint8_t *strtab)
{
	uint32_t nbuckets;
	uint32_t nchains;
        uint32_t *buckets;
        uint32_t *chains;
	uint32_t h;
	uint32_t idx;
 
	nbuckets = hashtab[0];
	nchains	 = hashtab[1];
	buckets  = hashtab + 2;
	chains	 = buckets + nbuckets;
 
	h = name_hash % nbuckets;
	for (idx = buckets[h]; idx != 0; idx = chains[idx]) {
		if (elf_hash(symtab[idx].st_name + strtab) == name_hash)
			return symtab[idx].st_value;
	}
	return -1;
}



uint64_t get_image_base_from_auxv(char **argv) 
{
	Elf64_auxv_t *auxv;

	/* walk past all argv pointers */
	while (*argv++ != NULL);

	/* walk past all env pointers */
	while (*argv++ != NULL);

	while (*argv++ != NULL) {
		auxv = (Elf64_auxv_t *)argv;
		if( auxv->a_type == AT_PHDR) {
			return ((auxv->a_un.a_val >> 12) << 12);
		}
	}
	return -1;
}

uint64_t resolve_symbol(struct link_map *l_map, uint32_t sym_hash) 
{
	Elf64_Dyn *dynamic;
        Elf64_Sym *sym_table;
        uint8_t *str_table = 0;
	uint32_t *hash_table = 0;
	uint64_t symbol_address = 0;
	
	dynamic = l_map->l_ld;

	while (dynamic->d_tag != DT_NULL) {
		switch (dynamic->d_tag) {
			case DT_HASH:
				hash_table = (dynamic->d_un.d_ptr < l_map->l_addr) ? 
					(uint32_t*)((uint8_t*)l_map->l_addr + dynamic->d_un.d_ptr):
					(uint32_t*)dynamic->d_un.d_ptr;
				break;
			case DT_SYMTAB:
				sym_table = (dynamic->d_un.d_ptr < l_map->l_addr) ? 
					(Elf64_Sym*)((uint8_t*)l_map->l_addr + dynamic->d_un.d_ptr):
					(Elf64_Sym*)dynamic->d_un.d_ptr;
				break;
			case DT_STRTAB:
				str_table = ((uint64_t)dynamic->d_un.d_ptr < l_map->l_addr) ? 
					(uint8_t*)((uint8_t*)l_map->l_addr + dynamic->d_un.d_ptr):
					(uint8_t*)dynamic->d_un.d_ptr;
				break;
		}
		dynamic++;
	}
	if (!hash_table || !sym_table || !str_table) {
		return -1;
	}
	symbol_address = lookup(sym_hash, hash_table, sym_table, str_table);
	symbol_address = symbol_address == -1 ? symbol_address : (uint64_t)((uint8_t*)symbol_address + l_map->l_addr);
	if (symbol_address == l_map->l_addr) {
		symbol_address = -1;
	}
	return symbol_address;
}

uint64_t * get_got(uint64_t image_base) {
	Elf64_Ehdr *ehdr = (Elf64_Ehdr*)image_base;
	Elf64_Phdr *phdr = (Elf64_Phdr*)((uint8_t*)image_base + ehdr->e_phoff);
	uint64_t *got;
	struct link_map *l_map;

	for(int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_DYNAMIC) {
			Elf64_Dyn *dyn = (Elf64_Dyn*)phdr[i].p_vaddr;
			while(dyn->d_tag != DT_NULL) {
				if (dyn->d_tag == DT_PLTGOT) {
					got = (uint64_t*)dyn->d_un.d_ptr;
					break;
				}
				dyn++;
			}
			break;
		}
	}
	return got;
}

unsigned long get_rip(void)
{
	unsigned long ret;

	__asm__ __volatile__
	(
	"call get_rip_label     \n"
	".globl get_rip_label   \n"
	"get_rip_label:         \n"
	"pop %%rax              \n"
	"mov %%rax, %0" : "=r"(ret)
	);

        return ret;
}


int resolve_got (int argc, char **argv) 
{
	uint64_t image_base;
	uint64_t *got;
	struct link_map *l_map;
	uint64_t symbol;
	bool skip_entry = false;

	if ((image_base = get_image_base_from_auxv(argv)) == -1) {
		return -1;
	}

	got = get_got(image_base);
	
	for (int i = 0; i < dynstr_size; i++) {
		l_map = (struct link_map*)got[1];
		do {
			uint64_t *addr = PIC_RESOLVE_ADDR(dynstr_buf);
			if(*(uint32_t*)((uint32_t*)addr + i) == 0){
				skip_entry = true;
				break;
			}
			symbol = resolve_symbol(l_map, *(uint32_t*)((uint32_t*)addr+i));
			l_map = l_map->l_next;
		} while(symbol == -1);
		if (skip_entry) {
			skip_entry = false;
			continue;
		}
		*(uint64_t*)&got[3+i] = symbol;
	}
}

