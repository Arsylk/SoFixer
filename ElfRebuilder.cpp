//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/6/4.
//                   Copyright (c) 2017. All rights reserved.
//===----------------------------------------------------------------------===//
#include "ElfRebuilder.h"
#include "FDebug.h"
#include "elf.h"
#include "macros.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <utility>
#include <vector>

#ifdef __LP64__
#define ADDRESS_FORMAT "ll"
#else
#define ADDRESS_FORMAT ""
#define R_ARM_RELATIVE 23
#define R_ARM_GLOB_DAT 21
#define R_ARM_JUMP_SLOT 22
#define R_ARM_ABS32 2
#define R_ARM_IRELATIVE 160
#endif

ElfRebuilder::ElfRebuilder(ObElfReader *elf_reader) {
  elf_reader_ = elf_reader;
  external_pointer = 0;
  si = *((soinfo *)malloc(sizeof(soinfo)));
}

bool ElfRebuilder::RebuildPhdr() {
  FLOGD("=============RebuildPhdr=========================");

  auto phdr = (Elf_Phdr *)elf_reader_->loaded_phdr();
  for (auto i = 0; i < elf_reader_->phdr_count(); i++) {
    phdr->p_filesz = phdr->p_memsz;
    phdr->p_paddr = phdr->p_vaddr;
    phdr->p_offset = phdr->p_vaddr;
    phdr++;
  }
  FLOGD("=====================RebuildPhdr End======================");
  return true;
}

bool ElfRebuilder::RebuildShdr() {
  FLOGD("=======================RebuildShdr=========================");

  auto base = si.load_bias;
  shstrtab.push_back('\0');

  // Empty shdr
  if (true) {
    Elf_Shdr shdr = {0};
    shdrs.push_back(shdr);
  }

  // gen .dynsym
  if (si.symtab != nullptr) {
    sDYNSYM = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".dynsym");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_DYNSYM;
    shdr.sh_flags = SHF_ALLOC;
    shdr.sh_addr = (uintptr_t)si.symtab - (uintptr_t)base;
    shdr.sh_offset = shdr.sh_addr;
    shdr.sh_size = 0;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
#ifdef __LP64__
    shdr.sh_addralign = 8;
    shdr.sh_entsize = sizeof(Elf64_Sym);
#else
    shdr.sh_addralign = 4;
    shdr.sh_entsize = sizeof(Elf32_Sym);
#endif
    shdrs.push_back(shdr);
  }

  // gen .dynstr
  if (si.strtab != nullptr) {
    sDYNSTR = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".dynstr");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_STRTAB;
    shdr.sh_flags = SHF_ALLOC;
    shdr.sh_addr = (uintptr_t)si.strtab - (uintptr_t)base;
    shdr.sh_offset = shdr.sh_addr;
    shdr.sh_size = si.strtabsize;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 1;
    shdr.sh_entsize = 0;
    shdrs.push_back(shdr);
  }

  // gen .hash or .gnu.hash
  if (si.gnu_hash != nullptr) {
    sGNUHASH = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".gnu.hash");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_GNU_HASH;
    shdr.sh_flags = SHF_ALLOC;
    shdr.sh_addr = (uintptr_t)si.gnu_hash - (uintptr_t)base;
    shdr.sh_offset = shdr.sh_addr;

    // Calculate gnu_hash size
    uint32_t *hash_data = (uint32_t *)si.gnu_hash;
    uint32_t nbuckets = hash_data[0];
    uint32_t symoffset = hash_data[1];
    uint32_t bloom_size = hash_data[2];

    // Size = header(16) + bloom(bloom_size*8) + buckets(nbuckets*4) +
    // chain(estimated)
    shdr.sh_size = 16 + bloom_size * sizeof(Elf_Addr) + nbuckets * 4;
    if (si.symtab && si.nchain > 0) {
      shdr.sh_size += (si.nchain - symoffset) * 4;
    }

    shdr.sh_link = sDYNSYM;
    shdr.sh_info = 0;
    shdr.sh_addralign = 8;
    shdr.sh_entsize = 0;
    shdrs.push_back(shdr);
  } else if (si.hash != nullptr) {
    sHASH = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".hash");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_HASH;
    shdr.sh_flags = SHF_ALLOC;
    shdr.sh_addr = (uintptr_t)si.hash - (uintptr_t)base;
    shdr.sh_offset = shdr.sh_addr;
    shdr.sh_size = (si.nbucket + si.nchain + 2) * sizeof(uint32_t);
    shdr.sh_link = sDYNSYM;
    shdr.sh_info = 0;
    shdr.sh_addralign = 4;
    shdr.sh_entsize = 4;
    shdrs.push_back(shdr);
  }

  // gen .rela.dyn (ARM64 uses RELA, not REL)
  if (si.rela != nullptr && si.rela_count > 0) {
    sRELADYN = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".rela.dyn");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_RELA;
    shdr.sh_flags = SHF_ALLOC;
    shdr.sh_addr = (uintptr_t)si.rela - (uintptr_t)base;
    shdr.sh_offset = shdr.sh_addr;
    shdr.sh_size = si.rela_count * sizeof(Elf_Rela);
    shdr.sh_link = sDYNSYM;
    shdr.sh_info = 0;
    shdr.sh_addralign = sizeof(Elf_Addr);
    shdr.sh_entsize = sizeof(Elf_Rela);
    shdrs.push_back(shdr);
  }

  // gen .rela.plt (ARM64 PLT uses RELA)
  if (si.plt_rela != nullptr && si.plt_rela_count > 0) {
    sRELAPLT = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".rela.plt");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_RELA;
    shdr.sh_flags = SHF_ALLOC | SHF_INFO_LINK;
    shdr.sh_addr = (uintptr_t)si.plt_rela - (uintptr_t)base;
    shdr.sh_offset = shdr.sh_addr;
    shdr.sh_size = si.plt_rela_count * sizeof(Elf_Rela);
    shdr.sh_link = sDYNSYM;
    shdr.sh_info = 0; // Will be set to .plt section index later
    shdr.sh_addralign = sizeof(Elf_Addr);
    shdr.sh_entsize = sizeof(Elf_Rela);
    shdrs.push_back(shdr);
  }

  // gen .plt
  if (si.plt_rela != nullptr && si.plt_rela_count > 0) {
    sPLT = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".plt");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_PROGBITS;
    shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;

    // Find PLT location (typically after .rela.plt)
    if (sRELAPLT != 0) {
      shdr.sh_addr = shdrs[sRELAPLT].sh_addr + shdrs[sRELAPLT].sh_size;
      // Align to 16 bytes for ARM64
      shdr.sh_addr = (shdr.sh_addr + 15) & ~15ULL;
    } else {
      shdr.sh_addr = 0; // Will be calculated later
    }
    shdr.sh_offset = shdr.sh_addr;
#ifdef __LP64__
    // ARM64 PLT: header(32 bytes) + entries(16 bytes each)
    shdr.sh_size = 32 + 16 * si.plt_rela_count;
    shdr.sh_addralign = 16;
#else
    // ARM32 PLT: header(20 bytes) + entries(12 bytes each)
    shdr.sh_size = 20 + 12 * si.plt_rela_count;
    shdr.sh_addralign = 4;
#endif
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_entsize = 0;
    shdrs.push_back(shdr);

    // Update .rela.plt sh_info to point to .plt
    if (sRELAPLT != 0) {
      shdrs[sRELAPLT].sh_info = sPLT;
    }
  }

  // gen .text
  if (si.plt_rel != nullptr || si.plt_rela != nullptr) {
    sTEXTTAB = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".text");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_PROGBITS;
    shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;

    if (sPLT != 0) {
      shdr.sh_addr = shdrs[sPLT].sh_addr + shdrs[sPLT].sh_size;
#ifdef __LP64__
      shdr.sh_addr = (shdr.sh_addr + 15) & ~15ULL; // 16-byte align
#else
      shdr.sh_addr = (shdr.sh_addr + 7) & ~7ULL; // 8-byte align
#endif
    } else {
      shdr.sh_addr = 0x1000; // Default
    }

    shdr.sh_offset = shdr.sh_addr;
    shdr.sh_size = 0; // Will be calculated later
    shdr.sh_link = 0;
    shdr.sh_info = 0;
#ifdef __LP64__
    shdr.sh_addralign = 16;
#else
    shdr.sh_addralign = 8;
#endif
    shdr.sh_entsize = 0;
    shdrs.push_back(shdr);
  }

  // gen .rodata (read-only data)
  if (true) {
    sRODATA = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".rodata");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_PROGBITS;
    shdr.sh_flags = SHF_ALLOC;
    shdr.sh_addr = 0; // Will be calculated
    shdr.sh_offset = shdr.sh_addr;
    shdr.sh_size = 0;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 16;
    shdr.sh_entsize = 0;
    shdrs.push_back(shdr);
  }

  // gen .fini_array
  if (si.fini_array != nullptr) {
    sFINIARRAY = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".fini_array");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_FINI_ARRAY;
    shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
    shdr.sh_addr = (uintptr_t)si.fini_array - (uintptr_t)base;
    shdr.sh_offset = shdr.sh_addr;
    shdr.sh_size = si.fini_array_count * sizeof(Elf_Addr);
    shdr.sh_link = 0;
    shdr.sh_info = 0;
#ifdef __LP64__
    shdr.sh_addralign = 8;
#else
    shdr.sh_addralign = 4;
#endif
    shdr.sh_entsize = 0;
    shdrs.push_back(shdr);
  }

  // gen .init_array
  if (si.init_array != nullptr) {
    sINITARRAY = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".init_array");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_INIT_ARRAY;
    shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
    shdr.sh_addr = (uintptr_t)si.init_array - (uintptr_t)base;
    shdr.sh_offset = shdr.sh_addr;
    shdr.sh_size = si.init_array_count * sizeof(Elf_Addr);
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = sizeof(Elf_Addr);
    shdr.sh_entsize = 0;

    shdrs.push_back(shdr);
  }

  // gen .dynamic
  if (si.dynamic != nullptr) {
    sDYNAMIC = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".dynamic");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_DYNAMIC;
    shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
    shdr.sh_addr = (uintptr_t)si.dynamic - (uintptr_t)base;
    shdr.sh_offset = shdr.sh_addr;
    shdr.sh_size = si.dynamic_count * sizeof(Elf_Dyn);
    shdr.sh_link = sDYNSTR;
    shdr.sh_info = 0;
    shdr.sh_addralign = sizeof(Elf_Addr);
    shdr.sh_entsize = sizeof(Elf_Dyn);

    shdrs.push_back(shdr);
  }

  // gen .got (Global Offset Table)
  if (si.plt_got != nullptr) {
    sGOT = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".got");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_PROGBITS;
    shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
    shdr.sh_addr = (uintptr_t)si.plt_got - (uintptr_t)base;
    shdr.sh_offset = shdr.sh_addr;

    // Estimate GOT size: 3 reserved entries + PLT entries
    shdr.sh_size = (3 + si.plt_rela_count) * sizeof(Elf_Addr);

    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = sizeof(Elf_Addr);
    shdr.sh_entsize = sizeof(Elf_Addr);

    shdrs.push_back(shdr);
  }

  // gen .data
  if (true) {
    sDATA = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".data");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_PROGBITS;
    shdr.sh_flags = SHF_ALLOC | SHF_WRITE;

    // Find highest address so far
    Elf_Addr max_addr = 0;
    for (size_t i = 1; i < shdrs.size(); i++) {
      Elf_Addr end = shdrs[i].sh_addr + shdrs[i].sh_size;
      if (end > max_addr)
        max_addr = end;
    }

    shdr.sh_addr = max_addr;
    shdr.sh_offset = shdr.sh_addr;
    shdr.sh_size = si.max_load - shdr.sh_addr;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 8;
    shdr.sh_entsize = 0;
    shdrs.push_back(shdr);
  }

  // gen .bss
  if (true) {
    sBSS = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".bss");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_NOBITS;
    shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
    shdr.sh_addr = si.max_load;
    shdr.sh_offset = si.max_load;
    shdr.sh_size = 0;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 8;
    shdr.sh_entsize = 0;
    shdrs.push_back(shdr);
  }

  // gen .shstrtab
  if (true) {
    sSHSTRTAB = shdrs.size();
    Elf_Shdr shdr = {0};

    shdr.sh_name = shstrtab.length();
    shstrtab.append(".shstrtab");
    shstrtab.push_back('\0');

    shdr.sh_type = SHT_STRTAB;
    shdr.sh_flags = 0;
    shdr.sh_addr = si.max_load;
    shdr.sh_offset = si.max_load;
    shdr.sh_size = shstrtab.length();
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 1;
    shdr.sh_entsize = 0;
    shdrs.push_back(shdr);
  }

  // Sort sections by address using stable sort to maintain relative order
  // Create index pairs for sorting
  std::vector<std::pair<Elf_Addr, size_t>> addr_index_pairs;
  for (size_t i = 1; i < shdrs.size(); i++) {
    addr_index_pairs.emplace_back(shdrs[i].sh_addr, i);
  }

  // Sort by address (stable sort maintains original order for equal addresses)
  std::stable_sort(
      addr_index_pairs.begin(), addr_index_pairs.end(),
      [](const std::pair<Elf_Addr, size_t> &a,
         const std::pair<Elf_Addr, size_t> &b) { return a.first < b.first; });

  // Create mapping from old indices to new indices
  std::vector<size_t> index_map(shdrs.size());
  index_map[0] = 0; // Keep null section at index 0

  for (size_t i = 0; i < addr_index_pairs.size(); i++) {
    size_t old_index = addr_index_pairs[i].second;
    size_t new_index = i + 1; // +1 because index 0 is reserved for null section
    index_map[old_index] = new_index;
  }

  // Reorder sections according to new mapping
  std::vector<Elf_Shdr> sorted_shdrs(shdrs.size());
  for (size_t i = 0; i < shdrs.size(); i++) {
    sorted_shdrs[index_map[i]] = shdrs[i];
  }
  shdrs = std::move(sorted_shdrs);

  // Update section index references using the mapping
  auto updateIndex = [&index_map](Elf_Word &index) {
    if (index != 0) {
      index = index_map[index];
    }
  };

  updateIndex(sDYNSYM);
  updateIndex(sDYNSTR);
  updateIndex(sHASH);
  updateIndex(sGNUHASH);
  updateIndex(sRELADYN);
  updateIndex(sRELAPLT);
  updateIndex(sPLT);
  updateIndex(sTEXT);
  updateIndex(sTEXTTAB);
  updateIndex(sRODATA);
  updateIndex(sFINIARRAY);
  updateIndex(sINITARRAY);
  updateIndex(sDYNAMIC);
  updateIndex(sGOT);
  updateIndex(sDATA);
  updateIndex(sBSS);
  updateIndex(sSHSTRTAB);

  // Fix section links
  if (sHASH != 0)
    shdrs[sHASH].sh_link = sDYNSYM;
  if (sGNUHASH != 0)
    shdrs[sGNUHASH].sh_link = sDYNSYM;
  if (sRELADYN != 0)
    shdrs[sRELADYN].sh_link = sDYNSYM;
  if (sRELAPLT != 0) {
    shdrs[sRELAPLT].sh_link = sDYNSYM;
    if (sPLT != 0)
      shdrs[sRELAPLT].sh_info = sPLT;
  }
  if (sDYNAMIC != 0)
    shdrs[sDYNAMIC].sh_link = sDYNSTR;
  if (sDYNSYM != 0)
    shdrs[sDYNSYM].sh_link = sDYNSTR;

  // Calculate sizes for sections with sh_size = 0
  if (sDYNSYM != 0 && shdrs[sDYNSYM].sh_size == 0) {
    for (size_t i = sDYNSYM + 1; i < shdrs.size(); i++) {
      if (shdrs[i].sh_addr > shdrs[sDYNSYM].sh_addr) {
        shdrs[sDYNSYM].sh_size = shdrs[i].sh_addr - shdrs[sDYNSYM].sh_addr;
        break;
      }
    }
  }

  if (sTEXT != 0 && shdrs[sTEXT].sh_size == 0) {
    for (size_t i = sTEXT + 1; i < shdrs.size(); i++) {
      if (shdrs[i].sh_addr > shdrs[sTEXT].sh_addr) {
        shdrs[sTEXT].sh_size = shdrs[i].sh_addr - shdrs[sTEXT].sh_addr;
        break;
      }
    }
  }

  if (sRODATA != 0 && shdrs[sRODATA].sh_size == 0) {
    for (size_t i = sRODATA + 1; i < shdrs.size(); i++) {
      if (shdrs[i].sh_addr > shdrs[sRODATA].sh_addr) {
        shdrs[sRODATA].sh_size = shdrs[i].sh_addr - shdrs[sRODATA].sh_addr;
        break;
      }
    }
  }

  FLOGD("=====================RebuildShdr End======================");
  return true;
}

bool ElfRebuilder::Rebuild() {
  return RebuildPhdr() && ReadSoInfo() && RebuildShdr() && RebuildRelocs() &&
         RebuildFin();
}

bool ElfRebuilder::ReadSoInfo() {
  FLOGD("=======================ReadSoInfo=========================");

  si.base = si.load_bias = elf_reader_->load_bias();
  si.phdr = elf_reader_->loaded_phdr();
  si.phnum = elf_reader_->phdr_count();
  auto base = si.load_bias;

  phdr_table_get_load_size(si.phdr, si.phnum, &si.min_load, &si.max_load);
  si.max_load += elf_reader_->pad_size_;

  si.dynamic = nullptr;
  si.dynamic_count = 0;
  si.dynamic_flags = 0;

  elf_reader_->GetDynamicSection(&si.dynamic, &si.dynamic_count,
                                 &si.dynamic_flags);
  if (si.dynamic == nullptr) {
    FLOGD("No valid dynamic section");
    return false;
  }
  FLOGD("dynamic: 0x%lx count: %zu", si.dynamic, si.dynamic_count);

  // Initialize pointers
  si.symtab = nullptr;
  si.strtab = nullptr;
  si.strtabsize = 0;
  si.hash = nullptr;
  si.gnu_hash = nullptr;
  si.nbucket = 0;
  si.nchain = 0;
  si.bucket = nullptr;
  si.chain = nullptr;
  si.plt_got = nullptr;
  si.plt_rela = nullptr;
  si.plt_rela_count = 0;
  si.rela = nullptr;
  si.rela_count = 0;
  si.rel = nullptr;
  si.rel_count = 0;
  si.init_array = nullptr;
  si.init_array_count = 0;
  si.fini_array = nullptr;
  si.fini_array_count = 0;
  si.init_func = nullptr;
  si.fini_func = nullptr;

  // Parse dynamic section
  for (Elf_Dyn *d = si.dynamic; d->d_tag != DT_NULL; ++d) {
    FLOGD("DT tag: 0x%lx value: 0x%lx", (unsigned long)d->d_tag,
          (unsigned long)d->d_un.d_val);

    switch (d->d_tag) {
    case DT_HASH:
      si.hash = base + d->d_un.d_ptr;
      si.nbucket = ((uint32_t *)(base + d->d_un.d_ptr))[0];
      si.nchain = ((uint32_t *)(base + d->d_un.d_ptr))[1];
      si.bucket = (uint32_t *)(base + d->d_un.d_ptr + 8);
      si.chain = (uint32_t *)(base + d->d_un.d_ptr + 8 + si.nbucket * 4);
      FLOGD("DT_HASH: nbucket=%u nchain=%u", si.nbucket, si.nchain);
      break;

    case DT_GNU_HASH:
      si.gnu_hash = base + d->d_un.d_ptr;
      FLOGD("DT_GNU_HASH at 0x%lx", d->d_un.d_ptr);
      break;

    case DT_STRTAB:
      si.strtab = (const char *)(base + d->d_un.d_ptr);
      FLOGD("DT_STRTAB at 0x%lx", d->d_un.d_ptr);
      break;

    case DT_STRSZ:
      si.strtabsize = d->d_un.d_val;
      FLOGD("DT_STRSZ: %zu", si.strtabsize);
      break;

    case DT_SYMTAB:
      si.symtab = (Elf_Sym *)(base + d->d_un.d_ptr);
      FLOGD("DT_SYMTAB at 0x%lx", d->d_un.d_ptr);
      break;

    case DT_SYMENT:
      if (d->d_un.d_val != sizeof(Elf_Sym)) {
        FLOGE("Invalid DT_SYMENT: %lu (expected %lu)",
              (unsigned long)d->d_un.d_val, (unsigned long)sizeof(Elf_Sym));
      }
      break;

    case DT_PLTREL:
      si.plt_type = d->d_un.d_val;
      FLOGD("DT_PLTREL: %lu (7=RELA, 17=REL)", (unsigned long)si.plt_type);
      break;

    case DT_JMPREL:
      if (si.plt_type == DT_RELA || si.plt_type == 0) {
        si.plt_rela = (Elf_Rela *)(base + d->d_un.d_ptr);
      } else {
        si.plt_rel = (Elf_Rel *)(base + d->d_un.d_ptr);
      }
      FLOGD("DT_JMPREL at 0x%lx", d->d_un.d_ptr);
      break;

    case DT_PLTRELSZ:
      if (si.plt_type == DT_RELA || si.plt_type == 0) {
        si.plt_rela_count = d->d_un.d_val / sizeof(Elf_Rela);
        FLOGD("DT_PLTRELSZ: %zu RELA entries", si.plt_rela_count);
      } else {
        si.plt_rel_count = d->d_un.d_val / sizeof(Elf_Rel);
        FLOGD("DT_PLTRELSZ: %zu REL entries", si.plt_rel_count);
      }
      break;

    case DT_RELA:
      si.rela = (Elf_Rela *)(base + d->d_un.d_ptr);
      FLOGD("DT_RELA at 0x%lx", d->d_un.d_ptr);
      break;

    case DT_RELASZ:
      si.rela_count = d->d_un.d_val / sizeof(Elf_Rela);
      FLOGD("DT_RELASZ: %zu entries", si.rela_count);
      break;

    case DT_RELAENT:
      if (d->d_un.d_val != sizeof(Elf_Rela)) {
        FLOGE("Invalid DT_RELAENT: %lu (expected %lu)",
              (unsigned long)d->d_un.d_val, (unsigned long)sizeof(Elf_Rela));
      }
      break;

    case DT_REL:
      si.rel = (Elf_Rel *)(base + d->d_un.d_ptr);
      FLOGD("DT_REL at 0x%lx", d->d_un.d_ptr);
      break;

    case DT_RELSZ:
      si.rel_count = d->d_un.d_val / sizeof(Elf_Rel);
      FLOGD("DT_RELSZ: %zu entries", si.rel_count);
      break;

    case DT_RELENT:
      if (d->d_un.d_val != sizeof(Elf_Rel)) {
        FLOGE("Invalid DT_RELENT: %lu (expected %lu)",
              (unsigned long)d->d_un.d_val, (unsigned long)sizeof(Elf_Rel));
      }
      break;

    case DT_PLTGOT:
      si.plt_got = (Elf_Addr *)(base + d->d_un.d_ptr);
      FLOGD("DT_PLTGOT at 0x%lx", d->d_un.d_ptr);
      break;

    case DT_INIT:
      si.init_func = (void *)(base + d->d_un.d_ptr);
      FLOGD("DT_INIT at 0x%lx", d->d_un.d_ptr);
      break;

    case DT_FINI:
      si.fini_func = (void *)(base + d->d_un.d_ptr);
      FLOGD("DT_FINI at 0x%lx", d->d_un.d_ptr);
      break;

    case DT_INIT_ARRAY:
      si.init_array = (void **)(base + d->d_un.d_ptr);
      FLOGD("DT_INIT_ARRAY at 0x%lx", d->d_un.d_ptr);
      break;

    case DT_INIT_ARRAYSZ:
      si.init_array_count = d->d_un.d_val / sizeof(Elf_Addr);
      FLOGD("DT_INIT_ARRAYSZ: %zu entries", si.init_array_count);
      break;

    case DT_FINI_ARRAY:
      si.fini_array = (void **)(base + d->d_un.d_ptr);
      FLOGD("DT_FINI_ARRAY at 0x%lx", d->d_un.d_ptr);
      break;

    case DT_FINI_ARRAYSZ:
      si.fini_array_count = d->d_un.d_val / sizeof(Elf_Addr);
      FLOGD("DT_FINI_ARRAYSZ: %zu entries", si.fini_array_count);
      break;

    case DT_PREINIT_ARRAY:
      si.preinit_array = (void **)(base + d->d_un.d_ptr);
      FLOGD("DT_PREINIT_ARRAY at 0x%lx", d->d_un.d_ptr);
      break;

    case DT_PREINIT_ARRAYSZ:
      si.preinit_array_count = d->d_un.d_val / sizeof(Elf_Addr);
      FLOGD("DT_PREINIT_ARRAYSZ: %zu entries", si.preinit_array_count);
      break;

    case DT_TEXTREL:
      si.has_text_relocations = true;
      FLOGD("DT_TEXTREL present");
      break;

    case DT_SYMBOLIC:
      si.has_DT_SYMBOLIC = true;
      FLOGD("DT_SYMBOLIC present");
      break;

    case DT_FLAGS:
      if (d->d_un.d_val & DF_TEXTREL) {
        si.has_text_relocations = true;
        FLOGD("DF_TEXTREL flag set");
      }
      if (d->d_un.d_val & DF_SYMBOLIC) {
        si.has_DT_SYMBOLIC = true;
        FLOGD("DF_SYMBOLIC flag set");
      }
      break;

    case DT_SONAME:
      si.soname = si.strtab + d->d_un.d_val;
      FLOGD("DT_SONAME: %p", si.soname);
      break;

    case DT_NEEDED:
    case DT_FLAGS_1:
    case DT_VERSYM:
    case DT_VERDEF:
    case DT_VERDEFNUM:
    case DT_VERNEED:
    case DT_VERNEEDNUM:
    case DT_RELCOUNT:
    case DT_RELACOUNT:
      // These are informational, no action needed
      break;

    default:
      FLOGD("Unknown/unhandled DT tag: 0x%lx", (unsigned long)d->d_tag);
      break;
    }
  }

  FLOGD("=======================ReadSoInfo End=========================");
  return true;
}

bool ElfRebuilder::RebuildFin() {
  FLOGD("=======================RebuildFin=========================");

  auto load_size = si.max_load - si.min_load;
  rebuild_size =
      load_size + shstrtab.length() + shdrs.size() * sizeof(Elf_Shdr);

  rebuild_data = new uint8_t[rebuild_size];
  if (!rebuild_data) {
    FLOGE("Failed to allocate %zu bytes for rebuild", rebuild_size);
    return false;
  }

  // Copy entire memory region
  memcpy(rebuild_data, (void *)si.load_bias, load_size);

  // Append .shstrtab
  memcpy(rebuild_data + load_size, shstrtab.c_str(), shstrtab.length());

  // Append section headers
  auto shdr_off = load_size + shstrtab.length();
  memcpy(rebuild_data + shdr_off, &shdrs[0], shdrs.size() * sizeof(Elf_Shdr));

  // Fix ELF header
  Elf_Ehdr ehdr = *elf_reader_->record_ehdr();
  ehdr.e_type = ET_DYN;
#ifdef __LP64__
  ehdr.e_machine = EM_AARCH64;
#else
  ehdr.e_machine = EM_ARM;
#endif
  ehdr.e_version = EV_CURRENT;
  ehdr.e_shnum = shdrs.size();
  ehdr.e_shoff = shdr_off;
  ehdr.e_shstrndx = sSHSTRTAB;
  ehdr.e_shentsize = sizeof(Elf_Shdr);

  memcpy(rebuild_data, &ehdr, sizeof(Elf_Ehdr));

  FLOGD("Rebuilt ELF: size=%zu shnum=%u shoff=0x%lx shstrndx=%u", rebuild_size,
        ehdr.e_shnum, (unsigned long)ehdr.e_shoff, ehdr.e_shstrndx);
  FLOGD("=======================RebuildFin End=========================");
  return true;
}

void ElfRebuilder::SaveImportSymNames() {
  FLOGD("%p", &si);
  if (si.symtab == nullptr || si.strtab == nullptr) {
    FLOGD("No symbol table available");
    return;
  }
  FLOGD("Symbol table available");

  FLOGD("=======================SaveImportSymNames=========================");

  mImports.clear();

  // Calculate symbol count
  size_t sym_count = 0;
  if (si.gnu_hash) {
    uint32_t *hash_data = (uint32_t *)si.gnu_hash;
    uint32_t nbuckets = hash_data[0];
    uint32_t symoffset = hash_data[1];
    uint32_t bloom_size = hash_data[2];

    uint32_t *buckets = &hash_data[4 + bloom_size * (sizeof(Elf_Addr) / 4)];
    uint32_t *chain = &buckets[nbuckets];

    // Find max symbol index
    sym_count = symoffset;
    for (uint32_t i = 0; i < nbuckets; i++) {
      if (buckets[i] != 0) {
        uint32_t idx = buckets[i];
        while ((chain[idx - symoffset] & 1) == 0) {
          idx++;
        }
        if (idx + 1 > sym_count) {
          sym_count = idx + 1;
        }
      }
    }
  } else if (si.hash) {
    sym_count = si.nchain;
  } else {
    FLOGD("No hash table, cannot determine symbol count");
    return;
  }

  FLOGD("Total symbols: %zu", sym_count);

  // Collect undefined symbols (imports)
  for (size_t i = 0; i < sym_count; i++) {
    Elf_Sym *sym = &si.symtab[i];

    // Skip if not undefined (imports have st_shndx == 0 and st_value == 0)
    if (sym->st_shndx != 0 || sym->st_value != 0) {
      continue;
    }

    if (sym->st_name == 0) {
      continue;
    }

    const char *symname = si.strtab + sym->st_name;
    if (symname && symname[0] != '\0') {
      mImports.push_back(symname);
      FLOGD("Import #%zu: %s", mImports.size() - 1, symname);
    }
  }

  FLOGD("Found %zu import symbols", mImports.size());
  FLOGD(
      "=======================SaveImportSymNames End=========================");
}

int ElfRebuilder::GetIndexOfImports(const std::string &symName) {
  for (size_t i = 0; i < mImports.size(); i++) {
    if (mImports[i] == symName) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

template <bool isRela>
void ElfRebuilder::relocate(uint8_t *base, Elf_Rel *rel, Elf_Addr dump_base) {
  if (!rel)
    return;

  auto type = ELF_R_TYPE(rel->r_info);
  auto sym = ELF_R_SYM(rel->r_info);
  auto reloc_addr = base + rel->r_offset;

#ifdef __LP64__
  // ARM64 relocations
  switch (type) {
  case R_AARCH64_RELATIVE: {
    // Relative relocation: *reloc_addr = base + addend
    Elf_Addr *ptr = (Elf_Addr *)reloc_addr;
    if (isRela) {
      Elf_Rela *rela = (Elf_Rela *)rel;
      *ptr = rela->r_addend; // Remove base, keep only addend
    } else {
      // For REL, value is already at location
      if (*ptr > dump_base) {
        *ptr = *ptr - dump_base;
      }
    }
    break;
  }

  case R_AARCH64_GLOB_DAT:
  case R_AARCH64_JUMP_SLOT: {
    // GOT/PLT relocations
    Elf_Addr *ptr = (Elf_Addr *)reloc_addr;

    if (sym < si.nchain && si.symtab) {
      Elf_Sym *syminfo = &si.symtab[sym];

      if (syminfo->st_value != 0) {
        // Defined symbol
        *ptr = syminfo->st_value;
      } else {
        // Undefined symbol (import)
        auto load_size = si.max_load - si.min_load;

        if (mImports.size() == 0) {
          *ptr = load_size + external_pointer;
          external_pointer += sizeof(Elf_Addr);
        } else {
          const char *symname = si.strtab + syminfo->st_name;
          int nIndex = GetIndexOfImports(symname);
          if (nIndex != -1) {
            *ptr = load_size + nIndex * sizeof(Elf_Addr);
          } else {
            FLOGD("Symbol not in imports: %s", symname);
          }
        }
      }
    }
    break;
  }

  case R_AARCH64_ABS64: {
    // Absolute 64-bit relocation
    Elf_Addr *ptr = (Elf_Addr *)reloc_addr;
    if (isRela) {
      Elf_Rela *rela = (Elf_Rela *)rel;
      if (sym < si.nchain && si.symtab) {
        Elf_Sym *syminfo = &si.symtab[sym];
        *ptr = syminfo->st_value + rela->r_addend;
      } else {
        *ptr = rela->r_addend;
      }
    } else {
      if (*ptr > dump_base) {
        *ptr = *ptr - dump_base;
      }
    }
    break;
  }

  case R_AARCH64_IRELATIVE: {
    // Indirect function relocation
    Elf_Addr *ptr = (Elf_Addr *)reloc_addr;
    if (isRela) {
      Elf_Rela *rela = (Elf_Rela *)rel;
      *ptr = rela->r_addend; // Keep resolver address as offset
    }
    FLOGD("IRELATIVE relocation at 0x%lx", rel->r_offset);
    break;
  }

  case R_AARCH64_COPY:
    FLOGD("R_AARCH64_COPY relocation type: %lu at offset 0x%lx", type,
          rel->r_offset);
    break;
  case R_AARCH64_P32_ABS32:
    FLOGD("R_AARCH64_P32_ABS32 relocation type: %lu at offset 0x%lx", type,
          rel->r_offset);
    break;
  case R_AARCH64_P32_ABS16:
    FLOGD("R_AARCH64_P32_ABS16 relocation type: %lu at offset 0x%lx", type,
          rel->r_offset);
    break;
  case R_AARCH64_P32_PREL32:
    FLOGD("R_AARCH64_P32_PREL32 relocation type: %lu at offset 0x%lx", type,
          rel->r_offset);
    break;
  case R_AARCH64_P32_PREL16:
    FLOGD("R_AARCH64_P32_PREL16 relocation type: %lu at offset 0x%lx", type,
          rel->r_offset);
    break;

  default:
    FLOGD("Unknown ARM64 relocation type: %lu at offset 0x%lx", type,
          rel->r_offset);
    break;
  }
#else
  // ARM32 relocations
  switch (type) {
  case R_ARM_RELATIVE: {
    Elf_Addr *ptr = (Elf_Addr *)reloc_addr;
    if (*ptr > dump_base) {
      *ptr = *ptr - dump_base;
    }
    break;
  }

  case R_ARM_GLOB_DAT:
  case R_ARM_JUMP_SLOT: {
    Elf_Addr *ptr = (Elf_Addr *)reloc_addr;

    if (sym < si.nchain && si.symtab) {
      Elf_Sym *syminfo = &si.symtab[sym];

      if (syminfo->st_value != 0) {
        *ptr = syminfo->st_value;
      } else {
        auto load_size = si.max_load - si.min_load;

        if (mImports.size() == 0) {
          *ptr = load_size + external_pointer;
          external_pointer += sizeof(Elf_Addr);
        } else {
          const char *symname = si.strtab + syminfo->st_name;
          int nIndex = GetIndexOfImports(symname);
          if (nIndex != -1) {
            *ptr = load_size + nIndex * sizeof(Elf_Addr);
          }
        }
      }
    }
    break;
  }

  case R_ARM_ABS32: {
    Elf_Addr *ptr = (Elf_Addr *)reloc_addr;
    if (*ptr > dump_base) {
      *ptr = *ptr - dump_base;
    }
    break;
  }

  case R_ARM_IRELATIVE: {
    Elf_Addr *ptr = (Elf_Addr *)reloc_addr;
    if (*ptr > dump_base) {
      *ptr = *ptr - dump_base;
    }
    FLOGD("IRELATIVE relocation at 0x%x", rel->r_offset);
    break;
  }

  default:
    FLOGD("Unknown ARM32 relocation type: %u at offset 0x%x", type,
          rel->r_offset);
    break;
  }
#endif
}

bool ElfRebuilder::RebuildRelocs() {
  FLOGD("=======================RebuildRelocs=========================");

  ElfRebuilder::SaveImportSymNames();
  FLOGD("saved imports");

  if (elf_reader_->dump_so_base_ == 0) {
    FLOGD("No dump_so_base, skipping relocation fixes");
    return true;
  }

  FLOGD("Fixing relocations (dump_base=0x%lx)", elf_reader_->dump_so_base_);

  auto base = (uint8_t *)si.load_bias;

  // Process .rela.dyn
  if (si.rela) {
    FLOGD("Processing %zu .rela.dyn entries", si.rela_count);
    for (size_t i = 0; i < si.rela_count; i++) {
      relocate<true>(base, (Elf_Rel *)&si.rela[i], elf_reader_->dump_so_base_);
    }
  }

  // Process .rela.plt
  if (si.plt_rela) {
    FLOGD("Processing %zu .rela.plt entries", si.plt_rela_count);
    for (size_t i = 0; i < si.plt_rela_count; i++) {
      relocate<true>(base, (Elf_Rel *)&si.plt_rela[i],
                     elf_reader_->dump_so_base_);
    }
  }

  // Process .rel.dyn (if any - rare on ARM64)
  if (si.rel) {
    FLOGD("Processing %zu .rel.dyn entries", si.rel_count);
    for (size_t i = 0; i < si.rel_count; i++) {
      relocate<false>(base, &si.rel[i], elf_reader_->dump_so_base_);
    }
  }

  // Process .rel.plt (if any - rare on ARM64)
  if (si.plt_rel && si.plt_type == DT_REL) {
    FLOGD("Processing %zu .rel.plt entries", si.plt_rel_count);
    for (size_t i = 0; i < si.plt_rel_count; i++) {
      relocate<false>(base, &si.plt_rel[i], elf_reader_->dump_so_base_);
    }
  }

  FLOGD("=======================RebuildRelocs End======================");
  return true;
}
