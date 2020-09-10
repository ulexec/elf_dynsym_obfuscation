#define _GNU_SOURCE
#include <libelfmaster.h>

#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TMP_FILE ".xyz.file"
#define PADDING_SIZE 1024
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE)
#define PAGE_ROUND(x) (PAGE_ALIGN_UP(x))

#define DYNSTR_MAX_LEN 8192 * 4

uint32_t dynstr_backup[DYNSTR_MAX_LEN];
unsigned long int dynstr_len;

#define MAX_SO_BASENAMES 1024

struct so_basenames {
	char *basename;
	uint32_t index;
} so_basenames[MAX_SO_BASENAMES];

uint32_t basename_count = 0;

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

bool
set_lazy_binding(elfobj_t *obj) 
{

	struct elf_section dynamic;
	Elf64_Dyn *dynamic_ptr;

	if (elf_section_by_name(obj, ".dynamic", &dynamic) == false) {
		fprintf(stderr, "couldn't find .dynstr section\n");
		return false;
	}

	dynamic_ptr = elf_offset_pointer(obj, dynamic.offset);
	if (dynamic_ptr == NULL) {
		fprintf(stderr, "Unable to locate offset: %#lx\n", dynamic.offset);
		return false;
	}

	do {
		if(dynamic_ptr->d_tag == DT_FLAGS && (dynamic_ptr->d_un.d_val & DF_BIND_NOW)){
			dynamic_ptr->d_un.d_val &= ~DF_BIND_NOW;
		} 
		/*if (dynamic_ptr->d_tag == DT_FLAGS_1 && (dynamic_ptr->d_un.d_val & DF_1_NOW)){
			dynamic_ptr->d_un.d_val &= ~DF_1_NOW;
		}*/
		dynamic_ptr++;
	} while(dynamic_ptr->d_tag != DT_NULL);
	return true;
}

bool
transform_dynstr_and_zero(elfobj_t *obj)
{
	struct elf_section dynstr;
	struct elf_section symtab;
	struct elf_section reltab;
	elf_dynamic_iterator_t iter;
	elf_dynamic_entry_t entry;
	uint8_t *strtab_ptr;
	Elf64_Sym *symtab_ptr;
	Elf64_Rela *reltab_ptr;
	int i, j, len;
	bool res;

	if (elf_section_by_name(obj, ".dynstr", &dynstr) == false) {
		fprintf(stderr, "couldn't find .dynstr section\n");
		return false;
	}

	strtab_ptr = elf_offset_pointer(obj, dynstr.offset);
	if (strtab_ptr == NULL) {
		fprintf(stderr, "Unable to locate offset: %#lx\n", dynstr.offset);
		return false;
	}
	if (dynstr.size >= DYNSTR_MAX_LEN) {
		fprintf(stderr, ".dynstr too large\n");
		return false;
	}

	/*
	 * Get offsets of imperative string table values for ld.so
	 */
	if (elf_section_by_name(obj, ".dynsym", &symtab) == false) {
		fprintf(stderr, "couldn't find .dynsym section (already stripped)\n");
		goto done;
	}
	
	symtab_ptr = elf_offset_pointer(obj, symtab.offset);

	if (elf_section_by_name(obj, ".rela.plt", &reltab) == false) {
		fprintf(stderr, "couldn't find .rela.plt section (already stripped)\n");
		goto done;
	}
	
	reltab_ptr = elf_offset_pointer(obj, reltab.offset);

	j = 0;
	for (i = 0; i < reltab.size/sizeof(Elf64_Rela); i++){
		Elf64_Rela *rel = &reltab_ptr[i];
		int symbol_index =  ELF64_R_SYM(rel->r_info);
		uint32_t hash;
		
		if (symtab_ptr[symbol_index].st_name == 0) {
			continue;
		} else if ((symtab_ptr[symbol_index].st_info & 0xf) != STT_FUNC) {
			continue;
		} else if (!strcmp(&strtab_ptr[symtab_ptr[symbol_index].st_name], "__libc_start_main")) {
			printf("[!] Skipping symbol:\t__libc_start_main\n");
			j++;
			continue;
		} 
	        printf("[*] Hashing symbol:\t%s\n", &strtab_ptr[symtab_ptr[symbol_index].st_name]);	
	        hash = elf_hash(&strtab_ptr[symtab_ptr[symbol_index].st_name]);
		*(uint32_t*)&dynstr_backup[j++] = hash;
	}

	dynstr_len = j ;

	for (i = 0; i < reltab.size/sizeof(Elf64_Rela); i++){
		Elf64_Rela *rel = &reltab_ptr[i];
		int symbol_index =  ELF64_R_SYM(rel->r_info);
		uint32_t hash;
		
		if (symtab_ptr[symbol_index].st_name == 0) {
			continue;
		} else if ((symtab_ptr[symbol_index].st_info & 0xf) != STT_FUNC) {
			continue;
		} else if (!strcmp(&strtab_ptr[symtab_ptr[symbol_index].st_name], "__libc_start_main")) {
			continue;
		} else if (strlen(&strtab_ptr[symtab_ptr[symbol_index].st_name]) <= 1) {
			continue;
		}
		memset(&strtab_ptr[symtab_ptr[symbol_index].st_name], 0, strlen(&strtab_ptr[symtab_ptr[symbol_index].st_name]));
	}



done:
	return true;
}

bool
inject_constructor(elfobj_t *obj)
{
	int i, j, fd;
	size_t old_size = obj->size;
	size_t stub_size;
	elfobj_t ctor_obj;
	elf_error_t error;
	unsigned long stub_vaddr;
	struct elf_symbol symbol;
	struct elf_section ctors;
	struct elf_section dynstr;
	uint8_t *ptr;

	if (elf_open_object("egg", &ctor_obj,
	    ELF_LOAD_F_STRICT|ELF_LOAD_F_MODIFY, &error) == false) {
	    fprintf(stderr, "%s\n", elf_error_msg(&error));
		exit(EXIT_FAILURE);
	}
	stub_size = ctor_obj.size;
	/*
	 * NOTE: We are directly modifying libelfmaster object's to update
	 * the program header table. This is not technically correct since
	 * its not using the libelfmaster API. Eventually libelfmaster will
	 * support this through accessor functions that are intended to modify
	 * meanwhile we are still using libelfmaster to speed up the process
	 * of creating this PoC for symbol and section lookups.
	 */
	for (i = 0; i < obj->ehdr64->e_phnum; i++) {
		if (obj->phdr64[i].p_type == PT_LOAD &&
		    obj->phdr64[i].p_offset == 0) {
			obj->phdr64[i].p_flags |= PF_W;
		}
		if (obj->phdr64[i].p_type == PT_DYNAMIC) {
			Elf64_Dyn *dyn = (Elf64_Dyn *)&obj->mem[obj->phdr64[i].p_offset];

			for (j = 0; dyn[j].d_tag != DT_NULL; j++) {
				if (dyn[j].d_tag == DT_VERNEEDNUM) {
					dyn[j].d_tag = 0;
				} else if (dyn[j].d_tag == DT_VERNEED) {
					dyn[j].d_tag = DT_DEBUG;
				}
			}
		}
		if (obj->phdr64[i].p_type == PT_NOTE) {
			obj->phdr64[i].p_type = PT_LOAD;
			obj->phdr64[i].p_vaddr = 0xc000000 + old_size;
			obj->phdr64[i].p_filesz = stub_size;
			obj->phdr64[i].p_memsz = obj->phdr64[i].p_filesz;
			obj->phdr64[i].p_flags = PF_R | PF_X | PF_W;
			obj->phdr64[i].p_paddr = obj->phdr64[i].p_vaddr;
			obj->phdr64[i].p_offset = old_size;
		}
	}
	/*
	 * For debugging purposes we can view our injected code
	 * with objdump by modifying an existing section header
	 * such as .eh_frame.
	 */
#if 0
	obj->shdr64[17].sh_size = stub_size;
	obj->shdr64[17].sh_addr = 0xc000000 + old_size;
	obj->shdr64[17].sh_offset = old_size;
#endif
	/*
	 * Locate .init_array so that we can modify the pointer to
	 * our injected constructor code 'egg (built from constructor.c)'
	 */
	if (elf_section_by_name(obj, ".init_array", &ctors) == false) {
		printf("Cannot find .init_array\n");
		return false;
	}

	/*
	 * Locate the symbol for the function restore_dynstr in our
	 * constructor so that we can find out where to hook the .init_array
	 * function pointer to.
	 */
	if (elf_symbol_by_name(&ctor_obj, "patch_got",
	    &symbol) == false) {
		printf("cannot find symbol \"patch_got\"\n");
		return false;
	}

	/*
	 * Get a pointer to .init_array function pointer
	 * so that we can hook it with our constructor
	 * entry point 'restore_dynstr'
	 */
	ptr = elf_offset_pointer(obj, ctors.offset);

	/*
	 * Because of the way that we build the constructor using 'gcc -N'
	 * it creates a single load segment that is not PAGE aligned, we must
	 * therefore PAGE align it to get the correct symbol_offset from the beginning
	 * of the ELF file.
	 */
	uint64_t symbol_offset = symbol.value - (elf_text_base(&ctor_obj) & ~4095);
	uint64_t entry_point = 0xc000000 + old_size + symbol_offset;

	/*
	 * Set the actual constructor hook with this memcpy.
	 * i.e. *(uint64_t *)&ptr[0] = entry_point;
	 */
	memcpy(ptr, &entry_point, sizeof(uint64_t));

	/*
	 * Get ready to write out our new final executable
	 * which includes the constructor code as a 3rd PT_LOAD
	 * segment
	 */
	fd = open(TMP_FILE, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU);
	if (fd < 0) {
		perror("open");
		return false;
	}

	/*
	 * Write out the original binary
	 */
	if (write(fd, obj->mem, old_size) != old_size) {
		perror("write");
		return false;
	}
	/*
	 *  open 'egg' and find the buffer to store the contents
	 * of dynstr (It is called dynstr_buf)
	 */
	if (elf_symbol_by_name(&ctor_obj, "dynstr_buf",
	    &symbol) == false) {
		fprintf(stderr, "Unable to find symbol dynstr_buf in egg binary\n");
		return false;
	}

	/*
	 * Patch egg so it has the .dynstr data in its
	 * char dynstr_buf[], so that at runtime it can
	 * restore it into the .dynstr section of the
	 * target executable that egg is injected into.
	 */
	ptr = elf_address_pointer(&ctor_obj, symbol.value);
	memcpy(ptr, dynstr_backup, dynstr_len * sizeof(uint64_t));

	/*
	 * Find dynstr_size variable within egg, and update it with the size
	 * of the .dynstr section.
	 */
	if (elf_symbol_by_name(&ctor_obj, "dynstr_size",
	    &symbol) == false) {
		fprintf(stderr, "Unable to find symbol dynstr_size in egg binary\n");
		return false;
	}
	ptr = elf_address_pointer(&ctor_obj, symbol.value);
	memcpy(ptr, &dynstr_len, sizeof(unsigned long int));

	/*zeroing out string table in egg*/
	if (elf_section_by_name(&ctor_obj, ".strtab", &dynstr) == false) {
		fprintf(stderr, "couldn't find .strtab section\n");
		return false;
	}

	ptr = elf_offset_pointer(&ctor_obj, dynstr.offset);
	if (ptr == NULL) {
		fprintf(stderr, "Unable to locate offset: %#lx\n", dynstr.offset);
		return false;
	}
	memset(ptr, 0, dynstr.size);

	/*zeroing out section headers string table in egg*/
	if (elf_section_by_name(&ctor_obj, ".shstrtab", &dynstr) == false) {
		fprintf(stderr, "couldn't find .shstrtab section\n");
		return false;
	}

	ptr = elf_offset_pointer(&ctor_obj, dynstr.offset);
	if (ptr == NULL) {
		fprintf(stderr, "Unable to locate offset: %#lx\n", dynstr.offset);
		return false;
	}
	memset(ptr, 0, dynstr.size);

	/*
	 * Append 'egg' constructor code to the end of the target binary
	 * the target binary has a PT_LOAD segment with corresponding offset
	 * and other values pointing to this injected code.
	 */
	if (write(fd, (char *)ctor_obj.mem, ctor_obj.size) != ctor_obj.size) {
		perror("write");
		return false;
	}
	if (rename(TMP_FILE, obj->path) < 0) {
		perror("rename");
		return false;
	}
	close(fd);
	(void) elf_close_object(&ctor_obj);
	return true;
}

int
main(int argc, char **argv)
{
	elfobj_t obj;
	elf_error_t error;
	bool res;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	if (elf_open_object(argv[1], &obj,
	    ELF_LOAD_F_STRICT|ELF_LOAD_F_MODIFY, &error) == false) {
		fprintf(stderr, "%s\n", elf_error_msg(&error));
		exit(EXIT_FAILURE);
	}

	printf("hashing dynstr\n");
	res = transform_dynstr_and_zero(&obj);

	printf("enabling lazy binding\n");
	set_lazy_binding(&obj);

	printf("Injecting constructor.o into %s\n", argv[1]);
	res = inject_constructor(&obj);

	printf("Commiting changes to %s\n", obj.path);
	elf_close_object(&obj);
}
	

