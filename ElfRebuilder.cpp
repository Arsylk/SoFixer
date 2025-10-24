//===------------------------------------------------------------*- C++ -*-===//
//                     ARM64 ELF Rebuilder - Improved Version
//===----------------------------------------------------------------------===//
#include "ElfRebuilder.h"
#include "FDebug.h"
#include "elf.h"
#include "macros.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

using Elf_Addr = Elf64_Addr;
using Elf_Off = Elf64_Off;
using Elf_Ehdr = Elf64_Ehdr;
using Elf_Phdr = Elf64_Phdr;
using Elf_Shdr = Elf64_Shdr;
using Elf_Sym = Elf64_Sym;
using Elf_Dyn = Elf64_Dyn;
using Elf_Rela = Elf64_Rela;
using Elf_Addr_Type = uint64_t;

class ImprovedElfRebuilder {
public:
  explicit ImprovedElfRebuilder(ObElfReader *reader) : elf_reader_(reader) {
    if (!reader) {
      throw std::runtime_error("Null ELF reader");
    }
  }

  bool Rebuild() {
    try {
      if (!ParseDynamicSection()) {
        FLOGE("Failed to parse dynamic section");
        return false;
      }

      if (!RebuildProgramHeaders()) {
        FLOGE("Failed to rebuild program headers");
        return false;
      }

      if (!RebuildSectionHeaders()) {
        FLOGE("Failed to rebuild section headers");
        return false;
      }

      if (!ProcessRelocations()) {
        FLOGE("Failed to process relocations");
        return false;
      }

      if (!FinalizeRebuild()) {
        FLOGE("Failed to finalize rebuild");
        return false;
      }

      return true;
    } catch (const std::exception &e) {
      FLOGE("Rebuild exception: %s", e.what());
      return false;
    }
  }

  const uint8_t *GetRebuildData() const { return rebuild_data_.get(); }
  size_t GetRebuildSize() const { return rebuild_size_; }
  const std::vector<std::string> &GetImports() const { return imports_; }

public:
  struct SectionInfo {
    std::string name;
    uint32_t type;
    uint64_t flags;
    Elf_Addr addr;
    Elf_Off offset;
    uint64_t size;
    uint32_t link;
    uint32_t info;
    uint64_t addralign;
    uint64_t entsize;

    SectionInfo(const std::string &n = "")
        : name(n), type(SHT_NULL), flags(0), addr(0), offset(0), size(0),
          link(0), info(0), addralign(1), entsize(0) {}
  };

  struct DynamicInfo {
    Elf_Addr base = 0;
    Elf_Addr load_bias = 0;
    const Elf_Phdr *phdr = nullptr;
    size_t phnum = 0;
    Elf_Addr min_load = 0;
    Elf_Addr max_load = 0;

    const Elf_Dyn *dynamic = nullptr;
    size_t dynamic_count = 0;

    const Elf_Sym *symtab = nullptr;
    const char *strtab = nullptr;
    size_t strtab_size = 0;
    size_t sym_count = 0;

    const uint32_t *hash = nullptr;
    uint32_t nbucket = 0;
    uint32_t nchain = 0;

    const uint32_t *gnu_hash = nullptr;

    const Elf_Rela *rela_dyn = nullptr;
    size_t rela_dyn_count = 0;

    const Elf_Rela *rela_plt = nullptr;
    size_t rela_plt_count = 0;

    const Elf_Addr *pltgot = nullptr;

    const void **init_array = nullptr;
    size_t init_array_count = 0;

    const void **fini_array = nullptr;
    size_t fini_array_count = 0;
  };

  ObElfReader *elf_reader_;
  DynamicInfo dyn_info_;
  std::vector<SectionInfo> sections_;
  std::string shstrtab_;
  std::vector<std::string> imports_;
  std::unordered_map<std::string, size_t> import_indices_;
  std::unique_ptr<uint8_t[]> rebuild_data_;
  size_t rebuild_size_ = 0;

  // Parse dynamic section and populate dyn_info_
  bool ParseDynamicSection() {
    FLOGD("=== Parsing Dynamic Section ===");

    dyn_info_.base = dyn_info_.load_bias = (Elf64_Addr)elf_reader_->load_bias();
    dyn_info_.phdr = elf_reader_->loaded_phdr();
    dyn_info_.phnum = elf_reader_->phdr_count();

    if (!phdr_table_get_load_size(dyn_info_.phdr, dyn_info_.phnum,
                                  &dyn_info_.min_load, &dyn_info_.max_load)) {
      FLOGE("Failed to get load size");
      return false;
    }

    dyn_info_.max_load += elf_reader_->pad_size_;

    Elf_Word dynamic_flags = 0;
    elf_reader_->GetDynamicSection(&dyn_info_.dynamic, &dyn_info_.dynamic_count,
                                   &dynamic_flags);

    if (!dyn_info_.dynamic) {
      FLOGE("No dynamic section found");
      return false;
    }

    FLOGD("Dynamic section: %p, count: %zu", dyn_info_.dynamic,
          dyn_info_.dynamic_count);

    // Parse all dynamic entries
    for (const Elf_Dyn *d = dyn_info_.dynamic; d->d_tag != DT_NULL; ++d) {
      ParseDynamicEntry(d);
    }

    // Calculate symbol count
    if (!CalculateSymbolCount()) {
      FLOGE("Failed to calculate symbol count");
      return false;
    }

    FLOGD("Symbol count: %zu", dyn_info_.sym_count);
    return true;
  }

  void ParseDynamicEntry(const Elf_Dyn *d) {
    auto base = dyn_info_.load_bias;

    switch (d->d_tag) {
    case DT_SYMTAB:
      dyn_info_.symtab =
          reinterpret_cast<const Elf_Sym *>(base + d->d_un.d_ptr);
      FLOGD("DT_SYMTAB: 0x%lx", d->d_un.d_ptr);
      break;

    case DT_STRTAB:
      dyn_info_.strtab = reinterpret_cast<const char *>(base + d->d_un.d_ptr);
      FLOGD("DT_STRTAB: 0x%lx", d->d_un.d_ptr);
      break;

    case DT_STRSZ:
      dyn_info_.strtab_size = d->d_un.d_val;
      FLOGD("DT_STRSZ: %zu", dyn_info_.strtab_size);
      break;

    case DT_HASH:
      dyn_info_.hash = reinterpret_cast<const uint32_t *>(base + d->d_un.d_ptr);
      dyn_info_.nbucket = dyn_info_.hash[0];
      dyn_info_.nchain = dyn_info_.hash[1];
      FLOGD("DT_HASH: nbucket=%u, nchain=%u", dyn_info_.nbucket,
            dyn_info_.nchain);
      break;

    case DT_GNU_HASH:
      dyn_info_.gnu_hash =
          reinterpret_cast<const uint32_t *>(base + d->d_un.d_ptr);
      FLOGD("DT_GNU_HASH: 0x%lx", d->d_un.d_ptr);
      break;

    case DT_RELA:
      dyn_info_.rela_dyn =
          reinterpret_cast<const Elf_Rela *>(base + d->d_un.d_ptr);
      FLOGD("DT_RELA: 0x%lx", d->d_un.d_ptr);
      break;

    case DT_RELASZ:
      dyn_info_.rela_dyn_count = d->d_un.d_val / sizeof(Elf_Rela);
      FLOGD("DT_RELASZ: %zu entries", dyn_info_.rela_dyn_count);
      break;

    case DT_JMPREL:
      dyn_info_.rela_plt =
          reinterpret_cast<const Elf_Rela *>(base + d->d_un.d_ptr);
      FLOGD("DT_JMPREL: 0x%lx", d->d_un.d_ptr);
      break;

    case DT_PLTRELSZ:
      dyn_info_.rela_plt_count = d->d_un.d_val / sizeof(Elf_Rela);
      FLOGD("DT_PLTRELSZ: %zu entries", dyn_info_.rela_plt_count);
      break;

    case DT_PLTGOT:
      dyn_info_.pltgot =
          reinterpret_cast<const Elf_Addr *>(base + d->d_un.d_ptr);
      FLOGD("DT_PLTGOT: 0x%lx", d->d_un.d_ptr);
      break;

    case DT_INIT_ARRAY:
      dyn_info_.init_array =
          reinterpret_cast<const void **>(base + d->d_un.d_ptr);
      FLOGD("DT_INIT_ARRAY: 0x%lx", d->d_un.d_ptr);
      break;

    case DT_INIT_ARRAYSZ:
      dyn_info_.init_array_count = d->d_un.d_val / sizeof(Elf_Addr);
      FLOGD("DT_INIT_ARRAYSZ: %zu", dyn_info_.init_array_count);
      break;

    case DT_FINI_ARRAY:
      dyn_info_.fini_array =
          reinterpret_cast<const void **>(base + d->d_un.d_ptr);
      FLOGD("DT_FINI_ARRAY: 0x%lx", d->d_un.d_ptr);
      break;

    case DT_FINI_ARRAYSZ:
      dyn_info_.fini_array_count = d->d_un.d_val / sizeof(Elf_Addr);
      FLOGD("DT_FINI_ARRAYSZ: %zu", dyn_info_.fini_array_count);
      break;

    case DT_PLTREL:
      if (d->d_un.d_val != DT_RELA) {
        FLOGW("Unexpected PLT relocation type: %lu (expected DT_RELA)",
              d->d_un.d_val);
      }
      break;

    default:
      // Ignore other tags
      break;
    }
  }

  bool CalculateSymbolCount() {
    if (!dyn_info_.symtab) {
      return false;
    }

    // Try GNU hash first (more reliable)
    if (dyn_info_.gnu_hash) {
      const uint32_t *hash = dyn_info_.gnu_hash;
      uint32_t nbuckets = hash[0];
      uint32_t symoffset = hash[1];
      uint32_t bloom_size = hash[2];

      const uint32_t *buckets =
          &hash[4 + bloom_size * 2]; // 2 = sizeof(Elf64_Addr)/sizeof(uint32_t)
      const uint32_t *chain = &buckets[nbuckets];

      dyn_info_.sym_count = symoffset;
      for (uint32_t i = 0; i < nbuckets; ++i) {
        if (buckets[i] >= symoffset) {
          uint32_t idx = buckets[i];
          // Follow chain until we hit the terminator bit
          while (idx < 0x10000) { // Safety limit
            if (chain[idx - symoffset] & 1) {
              // Last symbol in chain
              if (idx + 1 > dyn_info_.sym_count) {
                dyn_info_.sym_count = idx + 1;
              }
              break;
            }
            ++idx;
          }
        }
      }
      return true;
    }

    // Fall back to traditional hash
    if (dyn_info_.hash) {
      dyn_info_.sym_count = dyn_info_.nchain;
      return true;
    }

    // Last resort: estimate from string table size
    if (dyn_info_.strtab && dyn_info_.strtab_size > 0) {
      // Rough estimate: average symbol name ~20 bytes
      dyn_info_.sym_count = dyn_info_.strtab_size / 20;
      FLOGW("Estimating symbol count: %zu", dyn_info_.sym_count);
      return true;
    }

    return false;
  }

  bool RebuildProgramHeaders() {
    FLOGD("=== Rebuilding Program Headers ===");

    // Normalize all PT_LOAD segments
    Elf_Phdr *phdr = const_cast<Elf_Phdr *>(dyn_info_.phdr);
    for (size_t i = 0; i < dyn_info_.phnum; ++i) {
      if (phdr[i].p_type == PT_LOAD) {
        phdr[i].p_filesz = phdr[i].p_memsz;
        phdr[i].p_paddr = phdr[i].p_vaddr;
        phdr[i].p_offset = phdr[i].p_vaddr;
        FLOGD("PT_LOAD[%zu]: vaddr=0x%lx, memsz=0x%lx", i, phdr[i].p_vaddr,
              phdr[i].p_memsz);
      }
    }

    return true;
  }

  bool RebuildSectionHeaders() {
    FLOGD("=== Rebuilding Section Headers ===");

    sections_.clear();
    shstrtab_.clear();
    shstrtab_.push_back('\0'); // Null string at offset 0

    // Add null section
    sections_.emplace_back();

    // Build sections in memory order
    AddDynSymSection();
    AddDynStrSection();
    AddHashSection();
    AddRelaDynSection();
    AddRelaPltSection();
    AddPltSection();
    AddTextSection();
    AddInitArraySection();
    AddFiniArraySection();
    AddDynamicSection();
    AddGotSection();
    AddDataSection();
    AddBssSection();

    // Add .shstrtab last (address-independent)
    AddShStrTabSection();

    // Sort sections by address (excluding null and shstrtab)
    SortSections();

    // Fix cross-references
    FixSectionLinks();

    FLOGD("Created %zu sections", sections_.size());
    return true;
  }

  size_t AddStringToShStrTab(const std::string &str) {
    size_t offset = shstrtab_.size();
    shstrtab_.append(str);
    shstrtab_.push_back('\0');
    return offset;
  }

  void AddDynSymSection() {
    if (!dyn_info_.symtab || dyn_info_.sym_count == 0) {
      return;
    }

    SectionInfo sec(".dynsym");
    sec.type = SHT_DYNSYM;
    sec.flags = SHF_ALLOC;
    sec.addr =
        reinterpret_cast<Elf_Addr>(dyn_info_.symtab) - dyn_info_.load_bias;
    sec.offset = sec.addr;
    sec.size = dyn_info_.sym_count * sizeof(Elf_Sym);
    sec.addralign = 8;
    sec.entsize = sizeof(Elf_Sym);
    sections_.push_back(sec);

    FLOGD("Added .dynsym: addr=0x%lx, size=0x%lx, count=%zu", sec.addr,
          sec.size, dyn_info_.sym_count);
  }

  void AddDynStrSection() {
    if (!dyn_info_.strtab || dyn_info_.strtab_size == 0) {
      return;
    }

    SectionInfo sec(".dynstr");
    sec.type = SHT_STRTAB;
    sec.flags = SHF_ALLOC;
    sec.addr =
        reinterpret_cast<Elf_Addr>(dyn_info_.strtab) - dyn_info_.load_bias;
    sec.offset = sec.addr;
    sec.size = dyn_info_.strtab_size;
    sec.addralign = 1;
    sections_.push_back(sec);

    FLOGD("Added .dynstr: addr=0x%lx, size=0x%lx", sec.addr, sec.size);
  }

  void AddHashSection() {
    if (dyn_info_.gnu_hash) {
      SectionInfo sec(".gnu.hash");
      sec.type = SHT_GNU_HASH;
      sec.flags = SHF_ALLOC;
      sec.addr =
          reinterpret_cast<Elf_Addr>(dyn_info_.gnu_hash) - dyn_info_.load_bias;
      sec.offset = sec.addr;

      // Calculate size: header + bloom + buckets + chains
      const uint32_t *hash = dyn_info_.gnu_hash;
      uint32_t nbuckets = hash[0];
      uint32_t symoffset = hash[1];
      uint32_t bloom_size = hash[2];

      sec.size = 16 +                            // header
                 bloom_size * sizeof(Elf_Addr) + // bloom filter
                 nbuckets * 4;                   // buckets

      // Estimate chain size
      if (dyn_info_.sym_count > symoffset) {
        sec.size += (dyn_info_.sym_count - symoffset) * 4;
      }

      sec.addralign = 8;
      sections_.push_back(sec);

      FLOGD("Added .gnu.hash: addr=0x%lx, size=0x%lx", sec.addr, sec.size);

    } else if (dyn_info_.hash) {
      SectionInfo sec(".hash");
      sec.type = SHT_HASH;
      sec.flags = SHF_ALLOC;
      sec.addr =
          reinterpret_cast<Elf_Addr>(dyn_info_.hash) - dyn_info_.load_bias;
      sec.offset = sec.addr;
      sec.size = (dyn_info_.nbucket + dyn_info_.nchain + 2) * sizeof(uint32_t);
      sec.addralign = 4;
      sec.entsize = 4;
      sections_.push_back(sec);

      FLOGD("Added .hash: addr=0x%lx, size=0x%lx", sec.addr, sec.size);
    }
  }

  void AddRelaDynSection() {
    if (!dyn_info_.rela_dyn || dyn_info_.rela_dyn_count == 0) {
      return;
    }

    SectionInfo sec(".rela.dyn");
    sec.type = SHT_RELA;
    sec.flags = SHF_ALLOC;
    sec.addr =
        reinterpret_cast<Elf_Addr>(dyn_info_.rela_dyn) - dyn_info_.load_bias;
    sec.offset = sec.addr;
    sec.size = dyn_info_.rela_dyn_count * sizeof(Elf_Rela);
    sec.addralign = 8;
    sec.entsize = sizeof(Elf_Rela);
    sections_.push_back(sec);

    FLOGD("Added .rela.dyn: addr=0x%lx, size=0x%lx, count=%zu", sec.addr,
          sec.size, dyn_info_.rela_dyn_count);
  }

  void AddRelaPltSection() {
    if (!dyn_info_.rela_plt || dyn_info_.rela_plt_count == 0) {
      return;
    }

    SectionInfo sec(".rela.plt");
    sec.type = SHT_RELA;
    sec.flags = SHF_ALLOC | SHF_INFO_LINK;
    sec.addr =
        reinterpret_cast<Elf_Addr>(dyn_info_.rela_plt) - dyn_info_.load_bias;
    sec.offset = sec.addr;
    sec.size = dyn_info_.rela_plt_count * sizeof(Elf_Rela);
    sec.addralign = 8;
    sec.entsize = sizeof(Elf_Rela);
    sections_.push_back(sec);

    FLOGD("Added .rela.plt: addr=0x%lx, size=0x%lx, count=%zu", sec.addr,
          sec.size, dyn_info_.rela_plt_count);
  }

  void AddPltSection() {
    if (!dyn_info_.rela_plt || dyn_info_.rela_plt_count == 0) {
      return;
    }

    SectionInfo sec(".plt");
    sec.type = SHT_PROGBITS;
    sec.flags = SHF_ALLOC | SHF_EXECINSTR;

    // PLT typically follows .rela.plt
    Elf_Addr plt_addr = reinterpret_cast<Elf_Addr>(dyn_info_.rela_plt) -
                        dyn_info_.load_bias +
                        dyn_info_.rela_plt_count * sizeof(Elf_Rela);
    plt_addr = (plt_addr + 15) & ~15ULL; // 16-byte align

    sec.addr = plt_addr;
    sec.offset = sec.addr;
    sec.size =
        32 +
        16 * dyn_info_.rela_plt_count; // ARM64: header(32) + entries(16 each)
    sec.addralign = 16;
    sections_.push_back(sec);

    FLOGD("Added .plt: addr=0x%lx, size=0x%lx", sec.addr, sec.size);
  }

  void AddTextSection() {
    // Find first executable PT_LOAD
    Elf_Addr text_start = 0;
    Elf_Addr text_end = 0;
    bool found = false;

    for (size_t i = 0; i < dyn_info_.phnum; ++i) {
      const Elf_Phdr &phdr = dyn_info_.phdr[i];
      if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
        if (!found || phdr.p_vaddr < text_start) {
          text_start = phdr.p_vaddr;
          found = true;
        }
        Elf_Addr end = phdr.p_vaddr + phdr.p_memsz;
        if (end > text_end) {
          text_end = end;
        }
      }
    }

    if (!found) {
      FLOGW("No executable segment found");
      return;
    }

    SectionInfo sec(".text");
    sec.type = SHT_PROGBITS;
    sec.flags = SHF_ALLOC | SHF_EXECINSTR;
    sec.addr = text_start;
    sec.offset = sec.addr;
    sec.size = text_end - text_start;
    sec.addralign = 16;
    sections_.push_back(sec);

    FLOGD("Added .text: addr=0x%lx, size=0x%lx", sec.addr, sec.size);
  }

  void AddInitArraySection() {
    if (!dyn_info_.init_array || dyn_info_.init_array_count == 0) {
      return;
    }

    SectionInfo sec(".init_array");
    sec.type = SHT_INIT_ARRAY;
    sec.flags = SHF_ALLOC | SHF_WRITE;
    sec.addr =
        reinterpret_cast<Elf_Addr>(dyn_info_.init_array) - dyn_info_.load_bias;
    sec.offset = sec.addr;
    sec.size = dyn_info_.init_array_count * sizeof(Elf_Addr);
    sec.addralign = 8;
    sections_.push_back(sec);

    FLOGD("Added .init_array: addr=0x%lx, size=0x%lx", sec.addr, sec.size);
  }

  void AddFiniArraySection() {
    if (!dyn_info_.fini_array || dyn_info_.fini_array_count == 0) {
      return;
    }

    SectionInfo sec(".fini_array");
    sec.type = SHT_FINI_ARRAY;
    sec.flags = SHF_ALLOC | SHF_WRITE;
    sec.addr =
        reinterpret_cast<Elf_Addr>(dyn_info_.fini_array) - dyn_info_.load_bias;
    sec.offset = sec.addr;
    sec.size = dyn_info_.fini_array_count * sizeof(Elf_Addr);
    sec.addralign = 8;
    sections_.push_back(sec);

    FLOGD("Added .fini_array: addr=0x%lx, size=0x%lx", sec.addr, sec.size);
  }

  void AddDynamicSection() {
    if (!dyn_info_.dynamic || dyn_info_.dynamic_count == 0) {
      return;
    }

    SectionInfo sec(".dynamic");
    sec.type = SHT_DYNAMIC;
    sec.flags = SHF_ALLOC | SHF_WRITE;
    sec.addr =
        reinterpret_cast<Elf_Addr>(dyn_info_.dynamic) - dyn_info_.load_bias;
    sec.offset = sec.addr;
    sec.size = dyn_info_.dynamic_count * sizeof(Elf_Dyn);
    sec.addralign = 8;
    sec.entsize = sizeof(Elf_Dyn);
    sections_.push_back(sec);

    FLOGD("Added .dynamic: addr=0x%lx, size=0x%lx", sec.addr, sec.size);
  }

  void AddGotSection() {
    if (!dyn_info_.pltgot) {
      return;
    }

    SectionInfo sec(".got");
    sec.type = SHT_PROGBITS;
    sec.flags = SHF_ALLOC | SHF_WRITE;
    sec.addr =
        reinterpret_cast<Elf_Addr>(dyn_info_.pltgot) - dyn_info_.load_bias;
    sec.offset = sec.addr;
    // GOT size: 3 reserved + PLT entries
    sec.size = (3 + dyn_info_.rela_plt_count) * sizeof(Elf_Addr);
    sec.addralign = 8;
    sec.entsize = sizeof(Elf_Addr);
    sections_.push_back(sec);

    FLOGD("Added .got: addr=0x%lx, size=0x%lx", sec.addr, sec.size);
  }

  void AddDataSection() {
    // Find highest writable address used by known sections
    Elf_Addr max_addr = 0;
    for (const auto &sec : sections_) {
      if (sec.flags & SHF_WRITE) {
        Elf_Addr end = sec.addr + sec.size;
        if (end > max_addr) {
          max_addr = end;
        }
      }
    }

    if (max_addr == 0) {
      // No writable sections found, use default
      max_addr = dyn_info_.max_load / 2;
    }

    SectionInfo sec(".data");
    sec.type = SHT_PROGBITS;
    sec.flags = SHF_ALLOC | SHF_WRITE;
    sec.addr = (max_addr + 7) & ~7ULL; // 8-byte align
    sec.offset = sec.addr;
    sec.size =
        (dyn_info_.max_load > sec.addr) ? (dyn_info_.max_load - sec.addr) : 0;
    sec.addralign = 8;
    sections_.push_back(sec);

    FLOGD("Added .data: addr=0x%lx, size=0x%lx", sec.addr, sec.size);
  }

  void AddBssSection() {
    SectionInfo sec(".bss");
    sec.type = SHT_NOBITS;
    sec.flags = SHF_ALLOC | SHF_WRITE;
    sec.addr = dyn_info_.max_load;
    sec.offset = dyn_info_.max_load;
    sec.size = 0; // BSS size unknown from memory dump
    sec.addralign = 8;
    sections_.push_back(sec);

    FLOGD("Added .bss: addr=0x%lx", sec.addr);
  }

  void AddShStrTabSection() {
    SectionInfo sec(".shstrtab");
    sec.type = SHT_STRTAB;
    sec.flags = 0;
    sec.addr = 0;   // Will be placed at end of file
    sec.offset = 0; // Will be set during finalization
    sec.size = 0;   // Will be calculated
    sec.addralign = 1;
    sections_.push_back(sec);
  }

  void SortSections() {
    // Separate sections with addresses from address-independent sections
    std::vector<SectionInfo> addressed_sections;
    std::vector<SectionInfo> unaddressed_sections;

    // Skip null section at index 0
    for (size_t i = 1; i < sections_.size(); ++i) {
      if (sections_[i].addr > 0 && sections_[i].type != SHT_STRTAB) {
        addressed_sections.push_back(sections_[i]);
      } else {
        unaddressed_sections.push_back(sections_[i]);
      }
    }

    // Sort addressed sections by address
    std::stable_sort(addressed_sections.begin(), addressed_sections.end(),
                     [](const SectionInfo &a, const SectionInfo &b) {
                       return a.addr < b.addr;
                     });

    // Rebuild sections vector: null + sorted addressed + unaddressed
    sections_.clear();
    sections_.emplace_back(); // Null section

    for (auto &sec : addressed_sections) {
      sections_.push_back(sec);
    }
    for (auto &sec : unaddressed_sections) {
      sections_.push_back(sec);
    }

    // Now assign string table names
    for (auto &sec : sections_) {
      if (!sec.name.empty()) {
        // Store name in shstrtab and remember offset (will be set in header)
        AddStringToShStrTab(sec.name);
      }
    }
  }

  void FixSectionLinks() {
    // Build name->index map
    std::unordered_map<std::string, size_t> name_to_index;
    for (size_t i = 0; i < sections_.size(); ++i) {
      if (!sections_[i].name.empty()) {
        name_to_index[sections_[i].name] = i;
      }
    }

    auto get_index = [&](const std::string &name) -> uint32_t {
      auto it = name_to_index.find(name);
      return (it != name_to_index.end()) ? it->second : 0;
    };

    // Fix links for each section type
    for (auto &sec : sections_) {
      if (sec.type == SHT_HASH || sec.type == SHT_GNU_HASH) {
        sec.link = get_index(".dynsym");
      } else if (sec.type == SHT_DYNSYM) {
        sec.link = get_index(".dynstr");
      } else if (sec.type == SHT_DYNAMIC) {
        sec.link = get_index(".dynstr");
      } else if (sec.type == SHT_RELA) {
        sec.link = get_index(".dynsym");
        if (sec.name == ".rela.plt") {
          sec.info = get_index(".plt");
        }
      }
    }

    FLOGD("Fixed section links");
  }

  bool ProcessRelocations() {
    FLOGD("=== Processing Relocations ===");

    // Extract import symbols first
    if (!ExtractImports()) {
      FLOGW("Failed to extract imports");
    }

    if (elf_reader_->dump_so_base_ == 0) {
      FLOGD("No dump base provided, skipping relocation fixes");
      return true;
    }

    uint8_t *base = reinterpret_cast<uint8_t *>(dyn_info_.load_bias);
    Elf_Addr dump_base = elf_reader_->dump_so_base_;

    // Process .rela.dyn
    if (dyn_info_.rela_dyn) {
      FLOGD("Processing %zu .rela.dyn relocations", dyn_info_.rela_dyn_count);
      for (size_t i = 0; i < dyn_info_.rela_dyn_count; ++i) {
        ProcessRelocation(base, &dyn_info_.rela_dyn[i], dump_base);
      }
    }

    // Process .rela.plt
    if (dyn_info_.rela_plt) {
      FLOGD("Processing %zu .rela.plt relocations", dyn_info_.rela_plt_count);
      for (size_t i = 0; i < dyn_info_.rela_plt_count; ++i) {
        ProcessRelocation(base, &dyn_info_.rela_plt[i], dump_base);
      }
    }

    FLOGD("Relocation processing complete");
    return true;
  }

  bool ExtractImports() {
    if (!dyn_info_.symtab || !dyn_info_.strtab || dyn_info_.sym_count == 0) {
      return false;
    }

    imports_.clear();
    import_indices_.clear();

    for (size_t i = 0; i < dyn_info_.sym_count; ++i) {
      const Elf_Sym &sym = dyn_info_.symtab[i];

      // Import symbols have: st_shndx == SHN_UNDEF and non-zero binding
      if (sym.st_shndx == SHN_UNDEF && sym.st_name != 0 &&
          ELF64_ST_BIND(sym.st_info) != STB_LOCAL) {

        const char *name = dyn_info_.strtab + sym.st_name;
        if (name && name[0] != '\0') {
          import_indices_[name] = imports_.size();
          imports_.push_back(name);
          FLOGD("Import[%zu]: %s (sym_idx=%zu)", imports_.size() - 1, name, i);
        }
      }
    }

    FLOGD("Extracted %zu import symbols", imports_.size());
    return true;
  }

  void ProcessRelocation(uint8_t *base, const Elf_Rela *rela,
                         Elf_Addr dump_base) {
    if (!rela) {
      return;
    }

    uint32_t type = ELF64_R_TYPE(rela->r_info);
    uint32_t sym = ELF64_R_SYM(rela->r_info);

    // Validate offset
    if (rela->r_offset >= dyn_info_.max_load) {
      FLOGW("Invalid relocation offset: 0x%lx", rela->r_offset);
      return;
    }

    Elf_Addr *reloc_ptr = reinterpret_cast<Elf_Addr *>(base + rela->r_offset);

    switch (type) {
    case R_AARCH64_NONE:
      break;

    case R_AARCH64_RELATIVE:
      // Base + Addend -> just store addend (remove base)
      *reloc_ptr = rela->r_addend;
      break;

    case R_AARCH64_GLOB_DAT:
    case R_AARCH64_JUMP_SLOT:
      ProcessGlobalRelocation(reloc_ptr, sym, rela->r_addend, dump_base);
      break;

    case R_AARCH64_ABS64:
      // Absolute 64-bit address
      if (sym < dyn_info_.sym_count && dyn_info_.symtab) {
        const Elf_Sym &syminfo = dyn_info_.symtab[sym];
        if (syminfo.st_value != 0) {
          // Defined symbol: symbol_value + addend
          *reloc_ptr = syminfo.st_value + rela->r_addend;
        } else {
          // Undefined: just addend
          *reloc_ptr = rela->r_addend;
        }
      } else {
        *reloc_ptr = rela->r_addend;
      }
      break;

    case R_AARCH64_IRELATIVE:
      // Indirect function: resolver address
      *reloc_ptr = rela->r_addend;
      FLOGD("IRELATIVE at 0x%lx -> 0x%lx", rela->r_offset, rela->r_addend);
      break;

    case R_AARCH64_COPY:
      FLOGW("R_AARCH64_COPY relocation at 0x%lx (not handled)", rela->r_offset);
      break;

    case R_AARCH64_ABS32:
      // 32-bit absolute relocation (rare on ARM64)
      if (sym < dyn_info_.sym_count && dyn_info_.symtab) {
        const Elf_Sym &syminfo = dyn_info_.symtab[sym];
        uint32_t *ptr32 = reinterpret_cast<uint32_t *>(reloc_ptr);
        *ptr32 = static_cast<uint32_t>(syminfo.st_value + rela->r_addend);
      }
      break;

    default:
      FLOGW("Unhandled relocation type %u at offset 0x%lx", type,
            rela->r_offset);
      break;
    }
  }

  void ProcessGlobalRelocation(Elf_Addr *reloc_ptr, uint32_t sym_idx,
                               Elf_Addr addend, Elf_Addr dump_base) {
    if (sym_idx >= dyn_info_.sym_count || !dyn_info_.symtab) {
      FLOGW("Invalid symbol index: %u (max: %zu)", sym_idx,
            dyn_info_.sym_count);
      return;
    }

    const Elf_Sym &sym = dyn_info_.symtab[sym_idx];

    if (sym.st_value != 0) {
      // Defined symbol: use symbol value
      *reloc_ptr = sym.st_value;
    } else {
      // Undefined symbol (import): assign synthetic address
      if (sym.st_name == 0 || !dyn_info_.strtab) {
        FLOGW("Invalid symbol name for import");
        *reloc_ptr = 0;
        return;
      }

      const char *sym_name = dyn_info_.strtab + sym.st_name;
      auto it = import_indices_.find(sym_name);

      if (it != import_indices_.end()) {
        // Place imports at end of .data section
        Elf_Addr import_base = dyn_info_.max_load;
        *reloc_ptr = import_base + it->second * sizeof(Elf_Addr);
        FLOGD("Import '%s' -> 0x%lx", sym_name, *reloc_ptr);
      } else {
        FLOGW("Symbol '%s' not found in imports", sym_name);
        *reloc_ptr = 0;
      }
    }
  }

  bool FinalizeRebuild() {
    FLOGD("=== Finalizing Rebuild ===");

    // Calculate file layout
    Elf_Addr load_size = dyn_info_.max_load - dyn_info_.min_load;

    // Update .shstrtab section with actual values
    for (auto &sec : sections_) {
      if (sec.name == ".shstrtab") {
        sec.offset = load_size;
        sec.addr = 0; // Not loaded in memory
        sec.size = shstrtab_.size();
        break;
      }
    }

    Elf_Off shdr_offset = load_size + shstrtab_.size();
    size_t shdr_table_size = sections_.size() * sizeof(Elf_Shdr);

    rebuild_size_ = shdr_offset + shdr_table_size;
    rebuild_data_ = std::make_unique<uint8_t[]>(rebuild_size_);

    if (!rebuild_data_) {
      FLOGE("Failed to allocate %zu bytes", rebuild_size_);
      return false;
    }

    // Copy loaded memory
    std::memcpy(rebuild_data_.get(),
                reinterpret_cast<const void *>(dyn_info_.load_bias), load_size);

    // Append .shstrtab
    std::memcpy(rebuild_data_.get() + load_size, shstrtab_.data(),
                shstrtab_.size());

    // Build and append section header table
    std::vector<Elf_Shdr> shdr_table = BuildSectionHeaderTable();
    std::memcpy(rebuild_data_.get() + shdr_offset, shdr_table.data(),
                shdr_table_size);

    // Fix ELF header
    if (!FixElfHeader(shdr_offset)) {
      FLOGE("Failed to fix ELF header");
      return false;
    }

    FLOGD("Rebuild complete: size=%zu bytes", rebuild_size_);
    FLOGD("  Load size: %lu", load_size);
    FLOGD("  .shstrtab size: %zu", shstrtab_.size());
    FLOGD("  Section headers: %zu entries (%zu bytes)", sections_.size(),
          shdr_table_size);

    return true;
  }

  std::vector<Elf_Shdr> BuildSectionHeaderTable() {
    std::vector<Elf_Shdr> shdr_table;
    shdr_table.reserve(sections_.size());

    // Build string table name offset map
    std::unordered_map<std::string, size_t> name_offsets;
    size_t offset = 1; // Skip null byte
    for (const auto &sec : sections_) {
      if (!sec.name.empty()) {
        name_offsets[sec.name] = offset;
        offset += sec.name.size() + 1;
      }
    }

    // Convert SectionInfo to Elf_Shdr
    for (const auto &sec : sections_) {
      Elf_Shdr shdr = {0};

      if (!sec.name.empty()) {
        auto it = name_offsets.find(sec.name);
        shdr.sh_name = (it != name_offsets.end()) ? it->second : 0;
      }

      shdr.sh_type = sec.type;
      shdr.sh_flags = sec.flags;
      shdr.sh_addr = sec.addr;
      shdr.sh_offset = sec.offset;
      shdr.sh_size = sec.size;
      shdr.sh_link = sec.link;
      shdr.sh_info = sec.info;
      shdr.sh_addralign = sec.addralign;
      shdr.sh_entsize = sec.entsize;

      shdr_table.push_back(shdr);
    }

    return shdr_table;
  }

  bool FixElfHeader(Elf_Off shdr_offset) {
    const Elf_Ehdr *orig_ehdr = elf_reader_->record_ehdr();
    if (!orig_ehdr) {
      FLOGE("No original ELF header");
      return false;
    }

    Elf_Ehdr new_ehdr = *orig_ehdr;

    // Set ELF identification
    std::memcpy(new_ehdr.e_ident, ELFMAG, SELFMAG);
    new_ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    new_ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    new_ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    new_ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;

    // Set header fields
    new_ehdr.e_type = ET_DYN;
    new_ehdr.e_machine = EM_AARCH64;
    new_ehdr.e_version = EV_CURRENT;

    // Find .shstrtab index
    uint16_t shstrndx = 0;
    for (size_t i = 0; i < sections_.size(); ++i) {
      if (sections_[i].name == ".shstrtab") {
        shstrndx = i;
        break;
      }
    }

    new_ehdr.e_shoff = shdr_offset;
    new_ehdr.e_shentsize = sizeof(Elf_Shdr);
    new_ehdr.e_shnum = sections_.size();
    new_ehdr.e_shstrndx = shstrndx;

    // Copy to rebuild data
    std::memcpy(rebuild_data_.get(), &new_ehdr, sizeof(Elf_Ehdr));

    FLOGD("ELF header fixed: shnum=%u, shoff=0x%lx, shstrndx=%u",
          new_ehdr.e_shnum, new_ehdr.e_shoff, new_ehdr.e_shstrndx);

    return true;
  }
};

// Public API wrapper to maintain compatibility
ElfRebuilder::ElfRebuilder(ObElfReader *elf_reader) {
  elf_reader_ = elf_reader;
  external_pointer = 0;
  si = *((soinfo *)malloc(sizeof(soinfo)));
}

bool ElfRebuilder::Rebuild() {
  try {
    ImprovedElfRebuilder rebuilder(elf_reader_);
    if (!rebuilder.Rebuild()) {
      return false;
    }

    // Copy results
    rebuild_size = rebuilder.GetRebuildSize();
    rebuild_data = new uint8_t[rebuild_size];
    std::memcpy(rebuild_data, rebuilder.GetRebuildData(), rebuild_size);

    // Copy imports
    mImports = rebuilder.GetImports();

    return true;
  } catch (const std::exception &e) {
    FLOGE("Rebuild failed: %s", e.what());
    return false;
  }
}
