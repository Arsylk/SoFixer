//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/6/4.
//                   Copyright (c) 2017. All rights reserved.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//

#ifndef ELFREBUILDER_H
#define ELFREBUILDER_H

#include "ObElfReader.h"
#include <string>
#include <vector>

#ifdef __LP64__
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym Elf64_Sym
#define Elf_Dyn Elf64_Dyn
#define Elf_Rel Elf64_Rel
#define Elf_Rela Elf64_Rela
#define Elf_Addr Elf64_Addr
#define Elf_Word Elf64_Word
#define Elf_Xword Elf64_Xword
#define Elf_Off Elf64_Off
#else
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym Elf32_Sym
#define Elf_Dyn Elf32_Dyn
#define Elf_Rel Elf32_Rel
#define Elf_Rela Elf32_Rela
#define Elf_Addr Elf32_Addr
#define Elf_Word Elf32_Word
#define Elf_Xword Elf32_Word
#define Elf_Off Elf32_Off
#endif

#define DT_GNU_HASH 0x6ffffef5
#define SHT_GNU_HASH 0x6ffffff6

// Soinfo structure to hold ELF metadata
struct soinfo {
public:
  // Base addresses
  uint8_t *base = 0;
  uint8_t *load_bias = 0;

  // Program headers
  const Elf_Phdr *phdr = nullptr;
  size_t phnum = 0;

  // Load info
  Elf_Addr min_load = 0;
  Elf_Addr max_load = 0;

  // Dynamic section
  Elf_Dyn *dynamic = nullptr;
  size_t dynamic_count = 0;
  Elf_Word dynamic_flags = 0;

  // Symbol table
  Elf_Sym *symtab = nullptr;
  const char *strtab = nullptr;
  size_t strtabsize = 0;

  // Hash tables
  uint8_t *hash = 0;     // Old-style hash
  uint8_t *gnu_hash = 0; // GNU hash
  uint32_t nbucket = 0;
  uint32_t nchain = 0;
  uint32_t *bucket = 0;
  uint32_t *chain = 0;

  // Relocations
  Elf_Rel *rel = nullptr;
  size_t rel_count = 0;

  Elf_Rela *rela = nullptr;
  size_t rela_count = 0;

  // PLT relocations
  Elf_Rel *plt_rel = nullptr;
  Elf_Rela *plt_rela = nullptr;
  size_t plt_rel_count = 0;
  size_t plt_rela_count = 0;
  Elf_Word plt_type = 0; // DT_REL or DT_RELA

  // GOT
  Elf_Addr *plt_got = 0;

  // Init/Fini functions
  void **init_array = nullptr;
  size_t init_array_count = 0;
  void **fini_array = 0;
  size_t fini_array_count = 0;
  void **preinit_array = nullptr;
  size_t preinit_array_count = 0;
  void *init_func = nullptr;
  void *fini_func = nullptr;

  // ARM-specific
  uint32_t *out_exidx = 0;
  size_t out_exidx_count = 0;

  // MIPS-specific (kept for compatibility)
  uint32_t mips_symtabno = 0;
  uint32_t mips_local_gotno = 0;
  uint32_t mips_gotsym = 0;

  // Flags
  bool has_text_relocations = 0;
  bool has_DT_SYMBOLIC = 0;

  // Name
  const char *name = "name";
  const char *soname = "soname";
};

class ElfRebuilder {
public:
  explicit ElfRebuilder(ObElfReader *elf_reader);
  ~ElfRebuilder() {
    if (rebuild_data) {
      delete[] rebuild_data;
      rebuild_data = nullptr;
    }
  }

  // Main rebuild function
  bool Rebuild();

  // Get rebuilt data
  uint8_t *getRebuildData() { return rebuild_data; }
  size_t getRebuildSize() { return rebuild_size; }

  // Import symbol management
  void SetImports(const std::vector<std::string> &imports) {
    mImports = imports;
  }
  std::vector<std::string> &GetImports() { return mImports; }

private:
  // Rebuild steps
  bool RebuildPhdr();
  bool RebuildShdr();
  bool ReadSoInfo();
  bool RebuildRelocs();
  bool RebuildFin();

  // Helper functions
  void SaveImportSymNames();
  int GetIndexOfImports(const std::string &symName);

  template <bool isRela>
  void relocate(uint8_t *base, Elf_Rel *rel, Elf_Addr dump_base);

public:
  ObElfReader *elf_reader_;
  soinfo si;

  // Section headers and string table
  std::vector<Elf_Shdr> shdrs;
  std::string shstrtab;

  // Section indices
  Elf_Word sDYNSYM = 0;
  Elf_Word sDYNSTR = 0;
  Elf_Word sHASH = 0;
  Elf_Word sGNUHASH = 0;
  Elf_Word sRELDYN = 0;
  Elf_Word sRELADYN = 0;
  Elf_Word sRELPLT = 0;
  Elf_Word sRELAPLT = 0;
  Elf_Word sPLT = 0;
  Elf_Word sTEXT = 0;
  Elf_Word sTEXTTAB = 0; // Legacy name, same as sTEXT
  Elf_Word sRODATA = 0;
  Elf_Word sARMEXIDX = 0;
  Elf_Word sFINIARRAY = 0;
  Elf_Word sINITARRAY = 0;
  Elf_Word sDYNAMIC = 0;
  Elf_Word sGOT = 0;
  Elf_Word sDATA = 0;
  Elf_Word sBSS = 0;
  Elf_Word sSHSTRTAB = 0;

  // Rebuilt data
  uint8_t *rebuild_data = nullptr;
  size_t rebuild_size = 0;

  // Import symbols
  std::vector<std::string> mImports;
  Elf_Addr external_pointer = 0;
};

// Helper functions for phdr operations
inline size_t phdr_table_get_load_size(const Elf_Phdr *phdr_table,
                                       size_t phdr_count,
                                       Elf_Addr *out_min_vaddr,
                                       Elf_Addr *out_max_vaddr) {
  Elf_Addr min_vaddr = UINTPTR_MAX;
  Elf_Addr max_vaddr = 0;

  for (size_t i = 0; i < phdr_count; ++i) {
    const Elf_Phdr *phdr = &phdr_table[i];

    if (phdr->p_type != PT_LOAD) {
      continue;
    }

    if (phdr->p_vaddr < min_vaddr) {
      min_vaddr = phdr->p_vaddr;
    }

    Elf_Addr end_vaddr = phdr->p_vaddr + phdr->p_memsz;
    if (end_vaddr > max_vaddr) {
      max_vaddr = end_vaddr;
    }
  }

  if (min_vaddr > max_vaddr) {
    min_vaddr = max_vaddr = 0;
  }

  *out_min_vaddr = min_vaddr;
  *out_max_vaddr = max_vaddr;
  return min_vaddr;
}

inline void phdr_table_get_out_exidx(const Elf_Phdr *phdr_table,
                                     size_t phdr_count, uint8_t *base,
                                     uint32_t **out_exidx, size_t *out_count) {
  *out_exidx = nullptr;
  *out_count = 0;

  const Elf_Phdr* phdr = phdr_table;
  const Elf_Phdr* phdr_limit = phdr + phdr_count;


  for (phdr = phdr_table; phdr < phdr_limit; phdr++) {

    if (phdr->p_type != PT_ARM_EXIDX)
      continue;
    *out_exidx = (uint32_t*)(base + phdr->p_vaddr);
    *out_count = (size_t)(phdr->p_memsz / sizeof(uint32_t));
    return;
  }
  // for (size_t i = 0; i < phdr_count; ++i) {
  //   const Elf_Phdr *phdr = &phdr_table[i];
  //
  //   if (phdr->p_type != PT_out_exidx) {
  //     continue;
  //   }
  //
  //   *out_exidx = reinterpret_cast<uint32_t *>(base + phdr->p_vaddr);
  //   *out_count = phdr->p_memsz / 8;
  //   break;
  // }
}

#endif // ELFREBUILDER_H
