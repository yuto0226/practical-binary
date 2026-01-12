/* Demonstrate the binary loader from ../inc/loader.cc */

#include <cstring>
#include <stdint.h>
#include <stdio.h>
#include <string>

#include "../inc/loader.h"

void hexdump(const uint8_t *buf, size_t len) {
  for (int i = 0; i < len; i++) {
    if (i % 0x10 == 0 && i)
      printf("\n");
    if (i % 0x10 == 0)
      printf("    %04x: ", i);

    printf("%02X ", buf[i]);
  }
}

void dump_all(const Binary *bin, const Section *sec, const Symbol *sym) {
  for (int i = 0; i < bin->sections.size(); i++) {
    sec = &bin->sections[i];
    printf("  0x%016jx %-8ju %-20s %s\n", sec->vma, sec->size,
           sec->name.c_str(),
           sec->type == Section::SEC_TYPE_CODE ? "CODE" : "DATA");
  }

  if (bin->symbols.size() > 0) {
    printf("scanned symbol tables\n");
    for (int i = 0; i < bin->symbols.size(); i++) {
      sym = &bin->symbols[i];
      printf("  %-40s 0x%016jx %4s %s\n", sym->name.c_str(), sym->addr,
             (sym->type & Symbol::SYM_TYPE_FUNC)  ? "FUNC"
             : (sym->type & Symbol::SYM_TYPE_OBJ) ? "OBJ"
                                                  : "UKN",
             sym->binding == Symbol::SYM_BIND_WEAK     ? "WEAK"
             : sym->binding == Symbol::SYM_BIND_LOCAL  ? "LOCAL"
             : sym->binding == Symbol::SYM_BIND_GLOBAL ? "GLOBAL"
                                                       : "");
    }
  }
}

int main(int argc, char *argv[]) {
  Binary bin;
  Section *sec;
  Symbol *sym;
  std::string fname;

  if (argc < 2) {
    printf("Usage: %s <binary> [section]\n", argv[0]);
    return 1;
  }

  fname.assign(argv[1]);
  if (load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0) {
    return 1;
  }

  printf("loaded binary '%s' %s/%s (%u bits) entry@0x%016jx\n",
         bin.filename.c_str(), bin.type_str.c_str(), bin.arch_str.c_str(),
         bin.bits, bin.entry);

  if (argc < 3) {
    dump_all(&bin, sec, sym);
  } else {
    for (int i = 0; i < bin.sections.size(); i++) {
      sec = &bin.sections[i];
      if (strcmp(sec->name.c_str(), argv[2]) != 0)
        continue;

      printf("  0x%016jx %-8ju %-20s %s\n", sec->vma, sec->size,
             sec->name.c_str(),
             sec->type == Section::SEC_TYPE_CODE ? "CODE" : "DATA");
      hexdump(sec->bytes, sec->size);
    }
  }

  unload_binary(&bin);

  return 0;
}
