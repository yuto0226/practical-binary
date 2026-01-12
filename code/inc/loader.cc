#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include <bfd.h>

#include "loader.h"

static bfd *open_bfd(std::string &fname) {
  static int bfd_inited = 0;

  bfd *bfd_h;

  if (!bfd_inited) {
    bfd_init();
    bfd_inited = 1;
  }

  // 開啟檔案
  // target 留 NULL 讓 bfd 偵測檔案類型
  bfd_h = bfd_openr(fname.c_str(), NULL);
  if (!bfd_h) {
    fprintf(stderr, "failed to open binary '%s' (%s)\n", fname.c_str(),
            bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  // 檢查檔案格式
  // bfd.h #L1912
  // typedef enum bfd_format
  //   {
  //     bfd_unknown = 0,   /* File format is unknown.  */
  //     bfd_object,        /* Linker/assembler/compiler output.  */
  //     bfd_archive,       /* Object archive file.  */
  //     bfd_core,          /* Core dump.  */
  //     bfd_type_end       /* Marks the end; don't use it!  */
  //   }
  // bfd_format;
  if (!bfd_check_format(bfd_h, bfd_object)) {
    fprintf(stderr, "file '%s' does not look like an executable (%s)\n",
            fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  // 重設錯誤
  /* Some versions of bfd_check_format pessimistically set a wrong_format
   * error before detecting the format, and then neglect to unset it once
   * the format has been detected. We unset it manually to prevent problems. */
  bfd_set_error(bfd_error_no_error);

  // 檢查是哪種 header aka "flavour"
  // bfd.h #L7547
  // enum bfd_flavour
  // {
  //   /* N.B. Update bfd_flavour_name if you change this.  */
  //   bfd_target_unknown_flavour,
  //   bfd_target_aout_flavour,
  //   bfd_target_coff_flavour,
  //   bfd_target_ecoff_flavour,
  //   bfd_target_xcoff_flavour,
  //   bfd_target_elf_flavour,
  //   bfd_target_tekhex_flavour,
  //   bfd_target_srec_flavour,
  //   bfd_target_verilog_flavour,
  //   bfd_target_ihex_flavour,
  //   bfd_target_som_flavour,
  //   bfd_target_msdos_flavour,
  //   bfd_target_evax_flavour,
  //   bfd_target_mmo_flavour,
  //   bfd_target_mach_o_flavour,
  //   bfd_target_pef_flavour,
  //   bfd_target_pef_xlib_flavour,
  //   bfd_target_sym_flavour
  // };
  if (bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour) {
    fprintf(stderr, "unrecognized format for binary '%s' (%s)\n", fname.c_str(),
            bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  return bfd_h;
}

// 輸入 bfd 開啟的檔案物件, Binary 物件指標
// 回傳 0 成功, -1 失敗
static int load_symbols_bfd(bfd *bfd_h, Binary *bin) {
  int ret;
  long n, nsyms, i;
  asymbol **bfd_symtab; // 符號表
  Symbol *sym;

  bfd_symtab = NULL;

  n = bfd_get_symtab_upper_bound(bfd_h); // 獲取符號表大小
  if (n < 0) {
    fprintf(stderr, "failed to read symtab (%s)\n",
            bfd_errmsg(bfd_get_error()));
    goto fail;
  } else if (n) {
    bfd_symtab = (asymbol **)malloc(n);
    if (!bfd_symtab) {
      fprintf(stderr, "out of memory\n");
      goto fail;
    }
    nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab); // 轉換符號表
    if (nsyms < 0) {
      fprintf(stderr, "failed to read symtab (%s)\n",
              bfd_errmsg(bfd_get_error()));
      goto fail;
    }
    for (i = 0; i < nsyms; i++) {
      sym = bin->find_sym_by_name(std::string(bfd_symtab[i]->name));
      bool is_global = bfd_symtab[i]->flags & BSF_GLOBAL;
      bool is_weak = bfd_symtab[i]->flags & BSF_WEAK;

      if (!sym) { // 不要覆蓋掉符號
        bin->symbols.push_back(Symbol());
        sym = &bin->symbols.back();
      }

      std::string type_name = bfd_symtab[i]->flags & BSF_FUNCTION ? "FUNC"
                              : bfd_symtab[i]->flags & BSF_OBJECT ? "OBJ"
                                                                  : "UKN";

      sym->type = bfd_symtab[i]->flags & BSF_FUNCTION ? Symbol::SYM_TYPE_FUNC
                  : bfd_symtab[i]->flags & BSF_OBJECT ? Symbol::SYM_TYPE_OBJ
                                                      : Symbol::SYM_TYPE_UKN;
      sym->binding = is_weak ? Symbol::SYM_BIND_WEAK
                             : (is_global ? Symbol::SYM_BIND_GLOBAL
                                          : Symbol::SYM_BIND_LOCAL);
      sym->name = std::string(bfd_symtab[i]->name);
      sym->addr = bfd_asymbol_value(bfd_symtab[i]);
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if (bfd_symtab)
    free(bfd_symtab);

  return ret;
}

// 動態符號表的東西
static int load_dynsym_bfd(bfd *bfd_h, Binary *bin) {
  int ret;
  long n, nsyms, i;
  asymbol **bfd_dynsym;
  Symbol *sym;

  bfd_dynsym = NULL;

  n = bfd_get_dynamic_symtab_upper_bound(bfd_h); // 取得符號表大小
  if (n < 0) {
    fprintf(stderr, "failed to read dynamic symtab (%s)\n",
            bfd_errmsg(bfd_get_error()));
    goto fail;
  } else if (n) {
    bfd_dynsym = (asymbol **)malloc(n);
    if (!bfd_dynsym) {
      fprintf(stderr, "out of memory\n");
      goto fail;
    }
    nsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsym); // 轉換成符號表
    if (nsyms < 0) {
      fprintf(stderr, "failed to read dynamic symtab (%s)\n",
              bfd_errmsg(bfd_get_error()));
      goto fail;
    }
    for (i = 0; i < nsyms; i++) {
      if (bfd_dynsym[i]->flags & BSF_FUNCTION) {
        bin->symbols.push_back(Symbol());
        sym = &bin->symbols.back();
        sym->type = Symbol::SYM_TYPE_FUNC;
        sym->name = std::string(bfd_dynsym[i]->name);
        sym->addr = bfd_asymbol_value(bfd_dynsym[i]);
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if (bfd_dynsym)
    free(bfd_dynsym);

  return ret;
}

static int load_sections_bfd(bfd *bfd_h, Binary *bin) {
  int bfd_flags;
  uint64_t vma, size;
  const char *secname;
  asection *bfd_sec;
  Section *sec;
  Section::SectionType sectype;

  for (bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next) {
    bfd_flags =
        bfd_get_section_flags(bfd_h, bfd_sec); // 用來檢查 seciton 的類型

    sectype = Section::SEC_TYPE_NONE;
    if (bfd_flags & SEC_CODE) {
      sectype = Section::SEC_TYPE_CODE;
    } else if (bfd_flags & SEC_DATA) {
      sectype = Section::SEC_TYPE_DATA;
    } else {
      continue;
    }

    // 取得 section 資料
    vma = bfd_section_vma(bfd_sec);
    size = bfd_section_size(bfd_sec);
    secname = bfd_section_name(bfd_sec);
    if (!secname)
      secname = "<unnamed>";

    bin->sections.push_back(Section());
    sec = &bin->sections.back();

    sec->binary = bin;
    sec->name = std::string(secname);
    sec->type = sectype;
    sec->vma = vma;
    sec->size = size;
    sec->bytes = (uint8_t *)malloc(size);
    if (!sec->bytes) {
      fprintf(stderr, "out of memory\n");
      return -1;
    }

    // 複製 section 內容
    if (!bfd_get_section_contents(bfd_h, bfd_sec, sec->bytes, 0, size)) {
      fprintf(stderr, "failed to read section '%s' (%s)\n", secname,
              bfd_errmsg(bfd_get_error()));
      return -1;
    }
  }

  return 0;
}

static int load_binary_bfd(std::string &fname, Binary *bin,
                           Binary::BinaryType type) {
  int ret;
  bfd *bfd_h;
  const bfd_arch_info_type *bfd_info;

  bfd_h = NULL;

  // 初始化 bfd 並開啟目標檔案，開啟的一定會是可執行檔
  bfd_h = open_bfd(fname);
  if (!bfd_h) {
    goto fail;
  }

  // 把 bfd 的資訊填進 Binary 類別
  bin->filename = std::string(fname);
  bin->entry = bfd_get_start_address(bfd_h); // entry point

  // 檔案的資訊可以在 (bfd_target*)xvec 裡面找到
  bin->type_str = std::string(bfd_h->xvec->name);
  // 這邊只接受 Linux 的 ELF 和 Windows 的 PE aka COFF
  switch (bfd_h->xvec->flavour) {
  case bfd_target_elf_flavour:
    bin->type = Binary::BIN_TYPE_ELF;
    break;
  case bfd_target_coff_flavour:
    bin->type = Binary::BIN_TYPE_PE;
    break;
  case bfd_target_unknown_flavour:
  default:
    fprintf(stderr, "unsupported binary type (%s)\n", bfd_h->xvec->name);
    goto fail;
  }

  // bfd.h #L1837
  bfd_info = bfd_get_arch_info(bfd_h);
  bin->arch_str = std::string(bfd_info->printable_name);
  switch (bfd_info->mach) {
  case bfd_mach_i386_i386:
    bin->arch = Binary::ARCH_X86;
    bin->bits = 32;
    break;
  case bfd_mach_x86_64:
    bin->arch = Binary::ARCH_X86;
    bin->bits = 64;
    break;
  default:
    fprintf(stderr, "unsupported architecture (%s)\n",
            bfd_info->printable_name);
    goto fail;
  }

  /* Symbol handling is best-effort only (they may not even be present) */
  load_symbols_bfd(bfd_h, bin);
  load_dynsym_bfd(bfd_h, bin);

  if (load_sections_bfd(bfd_h, bin) < 0)
    goto fail;

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if (bfd_h)
    bfd_close(bfd_h);

  return ret;
}

int load_binary(std::string &fname, Binary *bin, Binary::BinaryType type) {
  return load_binary_bfd(fname, bin, type);
}

void unload_binary(Binary *bin) {
  size_t i;
  Section *sec;

  for (i = 0; i < bin->sections.size(); i++) {
    sec = &bin->sections[i];
    if (sec->bytes) {
      free(sec->bytes);
    }
  }
}
