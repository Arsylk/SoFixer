//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/6/3.
//                   Copyright (c) 2017. All rights reserved.
//===----------------------------------------------------------------------===//
//  Parse and read elf file.
//===----------------------------------------------------------------------===//

#ifndef SOFIXER_ELFREADER_H
#define SOFIXER_ELFREADER_H

#include "FileReader.h"
#include "macros.h"

#include <cstddef>
#include <cstdint>
#include <memory.h>

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

#define DT_RELACOUNT 0x6ffffff9

class ElfRebuilder;
class ObElfReader;

class ElfReader {
public:
  ElfReader();
  virtual ~ElfReader();

  virtual bool Load();
  bool setSource(const char *source);

  size_t phdr_count() { return phdr_num_; }
  uint8_t *load_start() { return load_start_; }
  Elf_Addr load_size() { return load_size_; }
  uint8_t *load_bias() { return load_bias_; }
  const Elf_Phdr *loaded_phdr() { return loaded_phdr_; }

  const Elf_Ehdr *record_ehdr() { return &header_; }

public:
  bool ReadElfHeader();
  bool VerifyElfHeader();
  bool ReadProgramHeader();
  bool ReserveAddressSpace(uint32_t padding_size = 0);
  bool LoadSegments();
  bool FindPhdr();
  bool CheckPhdr(uint8_t *);
  // If I have change anything in phtr_table_, just apply the chagnes into
  // loaded_phdr.
  void ApplyPhdrTable();

  virtual void GetDynamicSection(const Elf_Dyn **dynamic, size_t *dynamic_count,
                                 Elf_Word *dynamic_flags);

  const char *name_;
  FileReader *source_ = nullptr;

  Elf_Ehdr header_;
  size_t phdr_num_;

  void *phdr_mmap_;
  Elf_Phdr *phdr_table_;
  Elf_Addr phdr_size_;

  // First page of reserved address space.
  uint8_t *load_start_;
  // Size in bytes of reserved address space.
  Elf_Addr load_size_;
  Elf_Addr pad_size_;
  size_t file_size;
  // Load bias.
  uint8_t *load_bias_;

  // Loaded phdr.
  const Elf_Phdr *loaded_phdr_;

public:
  friend class ElfRebuilder;
  friend class ObElfReader;
};

bool phdr_table_get_load_size(const Elf_Phdr *phdr_table, size_t phdr_count,
                              Elf_Addr *min_vaddr = NULL,
                              Elf_Addr *max_vaddr = NULL);

int phdr_table_protect_segments(const Elf_Phdr *phdr_table, int phdr_count,
                                uint8_t *load_bias);

int phdr_table_unprotect_segments(const Elf_Phdr *phdr_table, int phdr_count,
                                  uint8_t *load_bias);

int phdr_table_protect_gnu_relro(const Elf_Phdr *phdr_table, int phdr_count,
                                 uint8_t *load_bias);

int phdr_table_get_arm_exidx(const Elf_Phdr *phdr_table, int phdr_count,
                             uint8_t *load_bias, Elf_Addr **arm_exidx,
                             unsigned *arm_exidix_count);

void phdr_table_get_dynamic_section(const Elf_Phdr *phdr_table, int phdr_count,
                                    uint8_t *load_bias, Elf_Dyn **dynamic,
                                    size_t *dynamic_count,
                                    Elf_Word *dynamic_flags);

#endif // SOFIXER_ELFREADER_H