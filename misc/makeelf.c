#define _GNU_SOURCE

#include <libelf.h>
#include <gelf.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc < 2)
    return 1;

  elf_version(EV_CURRENT);
  int fildes = open(argv[1], O_RDWR|O_TRUNC|O_CREAT, 0644);
  Elf* elf;
  if ((elf = elf_begin(fildes, ELF_C_WRITE, (Elf *)0)) == 0)
    return 1;

  Elf64_Ehdr* ehdr = elf64_newehdr(elf);
  ehdr->e_type = ET_REL;
  ehdr->e_machine = 247; // BPF?
  ehdr->e_shstrndx = 1;

  if(!gelf_update_ehdr(elf, ehdr)) {
    perror("gelf_update_ehdr");
    return 1;
  }
  /* int i = 1; */
  /* Elf64_Phdr* phdr = elf64_newphdr(elf, i); */

  // null section seems to be automatically set
  // [1] strtab
  Elf_Scn* scn = elf_newscn(elf);
  Elf64_Shdr* sh = elf64_getshdr(scn);
  Elf_Data* data = elf_newdata(scn);

  char strtab[] = "\0"
    ".strtab\0"
    "mysection\0"
    "lisence\0"
    "_lisence\0"
    "cgroup/dev\0"
    "my_prog1\0"
    ".symtab\0"
    "__end__";
  size_t tabsize = sizeof(strtab);
  data->d_buf = malloc(tabsize);
  memcpy(data->d_buf, strtab, tabsize);
  data->d_size = tabsize;
  data->d_align = 1;

  sh->sh_size = tabsize;
  sh->sh_entsize = 0;
  sh->sh_type = SHT_STRTAB;
  sh->sh_addralign = 1;
  sh->sh_flags = 0;
  sh->sh_name = 1;
  if(!gelf_update_shdr(scn, sh)) {
    perror("gelf_update_shdr");
    return 1;
  }

  size_t size, idx;

  // [2] lisence
  idx = (char *)memmem((char *)strtab, tabsize, "lisence", sizeof("lisence")) - (char *)strtab;
  scn = elf_newscn(elf);
  sh = elf64_getshdr(scn);
  data = elf_newdata(scn);

  char ldata[] = "GPL";
  size = sizeof(ldata);
  data->d_buf = malloc(size);
  memcpy(data->d_buf, ldata, size);
  data->d_size = size;
  data->d_align = 1;

  sh->sh_size = size;
  sh->sh_entsize = 0;
  sh->sh_type = SHT_PROGBITS;
  sh->sh_addralign = 1;
  sh->sh_flags = SHF_ALLOC | SHF_WRITE;
  sh->sh_name = idx;
  if(!gelf_update_shdr(scn, sh)) {
    perror("gelf_update_shdr");
    return 1;
  }

  // [3] bpf prog section
  idx = (char *)memmem((char *)strtab, tabsize, "cgroup/dev", sizeof("cgroup/dev")) - (char *)strtab;
  scn = elf_newscn(elf);
  sh = elf64_getshdr(scn);
  data = elf_newdata(scn);

  char bpfdata[] =
    "\xb7\x00\x00\x00\x00\x00\x00\x00\x95\x00\x00\x00\x00\x00\x00";
  /* char bpfdata[] = */
  /*   "\xb7\x00\x00\x00\x01\x00\x00\x00\x95\x00\x00\x00\x00\x00\x00"; */
  size = sizeof(bpfdata); // align to 8
  data->d_buf = malloc(size);
  memcpy(data->d_buf, bpfdata, size);
  data->d_size = size;
  data->d_align = 8;

  sh->sh_size = size;
  sh->sh_entsize = 0;
  sh->sh_type = SHT_PROGBITS;
  sh->sh_addralign = 8;
  sh->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
  sh->sh_name = idx;
  if(!gelf_update_shdr(scn, sh)) {
    perror("gelf_update_shdr");
    return 1;
  }

  // [4] symtab
  idx = (char *)memmem((char *)strtab, tabsize, ".symtab", sizeof(".symtab")) - (char *)strtab;
  scn = elf_newscn(elf);
  sh = elf64_getshdr(scn);
  data = elf_newdata(scn);

  Elf64_Sym syms[3] = {{0}, {0}, {0}};

  syms[1].st_name = (char *)memmem((char *)strtab, tabsize, "_lisence", sizeof("_lisence")) - (char *)strtab;
  syms[1].st_info = (STB_GLOBAL<<4)|STT_OBJECT;
  syms[1].st_shndx = 2;
  syms[1].st_value = 0;
  syms[1].st_size = sizeof(ldata);

  syms[2].st_name = (char *)memmem((char *)strtab, tabsize, "my_prog1", sizeof("my_prog1")) - (char *)strtab;
  syms[2].st_info = (STB_GLOBAL<<4)|STT_FUNC;
  syms[2].st_shndx = 3;
  syms[2].st_value = 0;
  syms[2].st_size = sizeof(bpfdata);

  size = sizeof(syms);

  data->d_buf = malloc(size);
  memcpy(data->d_buf, syms, size);
  data->d_size = size;
  data->d_align = 8;

  sh->sh_size = size;
  sh->sh_entsize = size / 3;
  sh->sh_type = SHT_SYMTAB;
  sh->sh_info = 1; // idx of first global sym
  sh->sh_link = 1; // idx of strtab
  sh->sh_addralign = 8;
  sh->sh_flags = 0;
  sh->sh_name = idx;
  if(!gelf_update_shdr(scn, sh)) {
    perror("gelf_update_shdr");
    return 1;
  }

  // update all
  if (elf_update(elf, ELF_C_WRITE) == -1)
    perror("elf_update");
  if (elf_end(elf) == -1)
    perror("elf_end");

  return 0;
}
