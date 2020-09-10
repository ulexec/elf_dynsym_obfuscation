#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <elf.h>

#define PAGE_SIZE 		 4096
#define	PAGE_ALIGN(k) 		 (((k)+((PAGE_SIZE)-1))&(~((PAGE_SIZE)-1)))
#define PIC_RESOLVE_ADDR(target) (get_rip() - ((char *)&get_rip_label - (char *)target))

uint32_t dynstr_buf[8192] __attribute__((section(".data"), aligned(8))) = { [0 ... 8191] = 0};
unsigned long dynstr_size __attribute__((section(".data"))) = {0};
unsigned long g_image_base __attribute__((section(".data")));

extern unsigned long get_rip_label;

struct link_map {
	Elf64_Addr l_addr;
	char * l_name;
	Elf64_Dyn *l_ld;
	struct link_map *l_next;
	struct link_map *l_prev;
};

__attribute__((unused)) int _start(void)
{

		return 0;
}

uint32_t elf_hash(const unsigned char *name) 
{
	uint32_t h = 0, g;
	while (*name) {
		h = (h << 4) + *name++;
		g = h & 0xf0000000;
		if (g) {
			h ^= g >> 24;
		}
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

	/*skip all argv pointers */
	while (*argv++ != NULL);

	/*skip all env pointers */
	while (*argv++ != NULL);
	
	/*iterating Auxv entries*/
	while (*argv++ != NULL) {
		auxv = (Elf64_auxv_t *)argv;
		if( auxv->a_type == AT_PHDR) {
			return ((auxv->a_un.a_val >> 12) << 12);
		}
	}
	return -1;
}

uint64_t resolve_symbol_from_module(struct link_map *l_map, uint32_t sym_hash) 
{
	Elf64_Dyn *dynamic;
        Elf64_Sym *sym_table;
        uint8_t *str_table = 0;
	uint32_t *hash_table = 0;
	uint64_t symbol_address = 0;

	/*
  	 * Points to dynamic segment of the shared library
 	*/	
	dynamic = l_map->l_ld;

	/*
	 * Locate .dynstr symbol table, hash lookup, and .dynstr string table
	*/
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


/*
 * Once the resolver is called the stack and argument context
 * is already setup, since our resolver has replaced got[2]
 * and control is being transferred there from PLT-0 just the
 * same as if dl_runtime_resolve was being invoked.
 */
void resolve_entry (void) 
{
	uint64_t image_base;
	uint64_t *got;
	struct link_map *l_map;
	uint64_t symbol;
	bool skip_entry = false;
	uint64_t hash_num;
	uint64_t o_rsp;
	uint64_t o_rdi;
	uint64_t o_rsi;
	uint64_t o_rdx;
	uint64_t o_rcx;
	uint64_t o_r8;
	uint64_t o_r9;
	uint64_t o_ret;
	
	/*saving stack and argument context*/
	__asm__ __volatile__(	"mov %%rsp, %0" : "=r"(o_rsp));
	__asm__ __volatile__(	"mov %%rdi, %0" : "=r"(o_rdi));
	__asm__ __volatile__(	"mov %%rsi, %0" : "=r"(o_rsi));
	__asm__ __volatile__(	"mov %%rdx, %0" : "=r"(o_rdx));
	__asm__ __volatile__(	"mov %%rcx, %0" : "=r"(o_rcx));
	__asm__ __volatile__(	"mov %%r8, %0" : "=r"(o_r8));
	__asm__ __volatile__(	"mov %%r9, %0" : "=r"(o_r9));
	
	/*restoring RTLD's arguments in stack*/
	__asm__ __volatile__(	"mov %rbp, %rsp");
	__asm__ __volatile__(	"pop %%rax	\n"
				"pop %%rax	\n"
				"mov %%rax, %0" : "=r"(l_map));	
	__asm__ __volatile__(	"pop %%rax	\n"
				"mov %%rax, %0" : "=r"(hash_num));	
	__asm__ __volatile__(	"mov %%rsp, %0" : "=r"(o_ret));
	
	/*restoring original stack pointer*/
	__asm__ __volatile__(	"mov %0, %%rsp" :: "r"(o_rsp));

	/*Locate the GOT via dynamic segment*/
	got = get_got(g_image_base);
	
	do {
		uint64_t *addr = PIC_RESOLVE_ADDR(dynstr_buf);
		symbol = resolve_symbol_from_module(l_map, *(uint32_t*)((uint32_t*)addr+hash_num));
		l_map = l_map->l_next;
	} while(symbol == -1);
	
	/*resolving correspondent symbol GOT entry*/
	/*This line can be deleted and will force the custom resolver to resolve
	* an entry every time is called. Good for anti-analysis since the analyst
	* would have to track each entry to know what symbol it holds :) */
	*(uint64_t*)&got[3+hash_num] = symbol;
	
	/*jumping to resolve symbol with adequate arguments and return address*/
	
	__asm__ __volatile__(	"mov %0, %%rsp" :: "r"(o_ret));
	__asm__ __volatile__(	"mov %0, %%rdi" :: "r"(o_rdi));
	__asm__ __volatile__(	"mov %0, %%rsi" :: "r"(o_rsi));
	__asm__ __volatile__(	"mov %0, %%rdx" :: "r"(o_rdx));
	__asm__ __volatile__(	"mov %0, %%rcx" :: "r"(o_rcx));
	__asm__ __volatile__(	"mov %0, %%r8"  :: "r"(o_r8));
	__asm__ __volatile__(	"mov %0, %%r9"  :: "r"(o_r9));
	__asm__ __volatile__(	"jmpq *%0" ::  "r"(symbol));
}

int patch_got(int argc, char ** argv) 
{
	uint64_t image_base;
	uint64_t *got;

	if ((image_base = get_image_base_from_auxv(argv)) == -1) {
		return -1;
	}
	g_image_base = image_base;	
	got = get_got(image_base);
	
	/*replacing RTLD resolver for our custom one at GOT[2]*/
	*(uint64_t*)&got[2] = PIC_RESOLVE_ADDR(resolve_entry);
	return 0;
}


