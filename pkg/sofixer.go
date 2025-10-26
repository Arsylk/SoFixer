package sofixer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	ELFCLASS32      = 1
	ELFCLASS64      = 2
	PT_LOAD         = 1
	PT_DYNAMIC      = 2
	PT_PHDR         = 6
	PT_GNU_EH_FRAME = 0x6474e550
	PT_GNU_STACK    = 0x6474e551
	PT_GNU_RELRO    = 0x6474e552
	ET_DYN          = 3
	EM_AARCH64      = 183

	// Dynamic Tag Constants (DT_TAG)
	DT_NULL         = 0
	DT_NEEDED       = 1
	DT_PLTRELSZ     = 2
	DT_PLTGOT       = 3
	DT_HASH         = 4
	DT_STRTAB       = 5
	DT_SYMTAB       = 6
	DT_RELA         = 7
	DT_RELASZ       = 8
	DT_JMPREL       = 23
	DT_INIT_ARRAY   = 25
	DT_FINI_ARRAY   = 26
	DT_INIT_ARRAYSZ = 27
	DT_FINI_ARRAYSZ = 28
	DT_STRSZ        = 10
	DT_SYMENT       = 11
	DT_GNU_HASH     = 0x6ffffef5
	// AArch64 Relocation Types
	R_AARCH64_NONE      = 0
	R_AARCH64_RELATIVE  = 1027
	R_AARCH64_GLOB_DAT  = 1025
	R_AARCH64_JUMP_SLOT = 1026
	R_AARCH64_ABS64     = 257

	// Section Header Types (SHT)
	SHT_NULL       = 0
	SHT_PROGBITS   = 1
	SHT_SYMTAB     = 2
	SHT_STRTAB     = 3
	SHT_RELA       = 4
	SHT_DYNAMIC    = 6
	SHT_INIT_ARRAY = 14
	SHT_FINI_ARRAY = 15
	SHT_DYNSYM     = 11
	SHT_GNU_HASH   = 0x6ffffff6
	SHT_NOBITS     = 8 // Added SHT_NOBITS

	// Section Header Flags (SHF)
	SHF_WRITE     = 0x1
	SHF_ALLOC     = 0x2
	SHF_EXECINSTR = 0x4
	SHF_INFO_LINK = 0x40
)

// DynamicEntry represents a 64-bit dynamic section entry (Elf64_Dyn).
type DynamicEntry struct {
	Tag uint64 // Dynamic entry type
	Val uint64 // Value or pointer
}

// RelocationEntry represents a 64-bit relocation entry with explicit addend (Elf64_Rela).
type RelocationEntry struct {
	Offset uint64 // Address of reference
	Info   uint64 // Symbol index and type of relocation
	Addend int64  // Constant addend
}

// SectionHeader represents a 64-bit section header entry (Elf64_Shdr).
type SectionHeader struct {
	Name      uint32 // Section name (index into string table)
	Type      uint32 // Section type
	Flags     uint64 // Section flags
	Addr      uint64 // Address in memory
	Offset    uint64 // Offset in file
	Size      uint64 // Size of section in file
	Link      uint32 // Link to another section
	Info      uint32 // Additional section information
	Addralign uint64 // Section alignment
	Entsize   uint64 // Size of entries in section
}

// ELFHeader represents the main ELF header structure (e_ident + rest of header).
// We assume 64-bit for the rest of the header fields as per the project context (ARM64).
type ELFHeader struct {
	Magic      [4]byte // 0x00-0x03: Magic number
	Class      uint8   // 0x04: 32-bit or 64-bit
	Data       uint8   // 0x05: Little or big endian
	Version    uint8   // 0x06: ELF version
	OSABI      uint8   // 0x07: OS/ABI identification
	ABIVersion uint8   // 0x08: ABI version
	Padding    [7]byte // 0x09-0x0F: Unused
	Type       uint16  // 0x10-0x11: object file type
	Machine    uint16  // 0x12-0x13: architecture
	Version2   uint32  // 0x14-0x17: ELF version (again)
	Entry      uint64  // 0x18-0x1F: entry point virtual address
	PhdrOffset uint64  // 0x20-0x27: program header table file offset
	ShdrOffset uint64  // 0x28-0x2F: section header table file offset
	Flags      uint32  // 0x30-0x33: processor specific flags
	Ehsize     uint16  // 0x34-0x35: ELF header size
	Phentsize  uint16  // 0x36-0x37: size of an entry in the program header table
	Phnum      uint16  // 0x38-0x39: number of entries in the program header table
	Shentsize  uint16  // 0x3A-0x3B: size of an entry in the section header table
	Shnum      uint16  // 0x3C-0x3D: number of entries in the section header table
	Shstrndx   uint16  // 0x3E-0x3F: section header string table index
}

// ProgramHeader represents a 64-bit program header entry (Elf64_Phdr).
type ProgramHeader struct {
	Type   uint32 // Segment type
	Flags  uint32 // Segment flags
	Offset uint64 // Segment file offset
	Vaddr  uint64 // Segment virtual address
	Paddr  uint64 // Segment physical address
	Filesz uint64 // Segment file size
	Memsz  uint64 // Segment memory size
	Align  uint64 // Segment alignment
}

// FixELFHeaders attempts to fix common issues with ELF headers.
func FixELFHeaders(filePath string, baseAddr uint64) error {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// 1. Read and validate ELF header
	var header ELFHeader
	if err := binary.Read(file, binary.LittleEndian, &header); err != nil {
		return fmt.Errorf("failed to read ELF header: %w", err)
	}

	if header.Magic != [4]byte{0x7f, 'E', 'L', 'F'} {
		return fmt.Errorf("invalid ELF magic number: %x", header.Magic)
	}
	if header.Class != ELFCLASS64 {
		return fmt.Errorf("unsupported ELF class: %d (expected 64-bit)", header.Class)
	}
	if header.Phentsize != 56 { // sizeof(Elf64_Phdr)
		return fmt.Errorf("invalid program header entry size: %d (expected 56)", header.Phentsize)
	}

	// 2. Read Program Header Table (PHT)
	phtSize := uint64(header.Phnum) * uint64(header.Phentsize)
	if phtSize == 0 || header.Phnum > 1024 { // Sanity check for Phnum
		return fmt.Errorf("invalid number of program headers: %d", header.Phnum)
	}

	if _, err := file.Seek(int64(header.PhdrOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to program header table: %w", err)
	}

	phdrs := make([]ProgramHeader, header.Phnum)
	if err := binary.Read(file, binary.LittleEndian, &phdrs); err != nil {
		return fmt.Errorf("failed to read program header table: %w", err)
	}

	// 3. Apply fixes to Program Headers
	if err := fixProgramHeaders(file, &header, phdrs, baseAddr); err != nil {
		return fmt.Errorf("program header fix failed: %w", err)
	}

	// 4. Fix Dynamic Section
	if err := fixDynamicSection(file, phdrs, baseAddr); err != nil {
		return fmt.Errorf("dynamic section fix failed: %w", err)
	}

	// 5. Fix Relocations
	if err := fixRelocations(file, phdrs, baseAddr); err != nil {
		return fmt.Errorf("relocation fix failed: %w", err)
	}

	// 6. Rebuild and Write Section Header Table
	if err := rebuildSectionHeaders(filePath, file, &header, phdrs, baseAddr); err != nil {
		return fmt.Errorf("SHT rebuild failed: %w", err)
	}

	// 7. Rewrite the fixed PHT back to the file
	if _, err := file.Seek(int64(header.PhdrOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to program header table for writing: %w", err)
	}
	if err := binary.Write(file, binary.LittleEndian, phdrs); err != nil {
		return fmt.Errorf("failed to write fixed program header table: %w", err)
	}

	// 8. Rewrite the fixed ELF header (in case any fields were modified)
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to ELF header for writing: %w", err)
	}
	if err := binary.Write(file, binary.LittleEndian, &header); err != nil {
		return fmt.Errorf("failed to write fixed ELF header: %w", err)
	}

	return nil
}

// SectionInfo is a helper struct to build the SHT.
type SectionInfo struct {
	Name      string
	Type      uint32
	Flags     uint64
	Addr      uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Addralign uint64
	Entsize   uint64
}

// rebuildSectionHeaders reconstructs the Section Header Table and writes it to the end of the file.
func rebuildSectionHeaders(filePath string, file *os.File, header *ELFHeader, phdrs []ProgramHeader, baseAddr uint64) error {
	// 1. Read the fixed dynamic section to gather info
	var dynamicPhdr *ProgramHeader
	for i := range phdrs {
		if phdrs[i].Type == PT_DYNAMIC {
			dynamicPhdr = &phdrs[i]
			break
		}
	}

	if dynamicPhdr == nil {
		return fmt.Errorf("PT_DYNAMIC segment not found, cannot rebuild SHT")
	}

	entryCount := dynamicPhdr.Memsz / 16
	dynamicEntries := make([]DynamicEntry, entryCount)
	if _, err := file.Seek(int64(dynamicPhdr.Offset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to dynamic section for SHT info: %w", err)
	}
	if err := binary.Read(file, binary.LittleEndian, &dynamicEntries); err != nil {
		return fmt.Errorf("failed to read dynamic section for SHT info: %w", err)
	}

	// Map to hold dynamic values
	dynMap := make(map[uint64]uint64)
	for _, entry := range dynamicEntries {
		dynMap[entry.Tag] = entry.Val
	}

	// 2. Collect all necessary section information
	sections := []SectionInfo{
		{Name: "", Type: SHT_NULL, Addralign: 1}, // Null section at index 0
	}
	shstrtab := "\x00" // Section Header String Table starts with null byte
	shNameOffsets := make(map[string]uint32)

	// Helper to add string to shstrtab and return offset
	addShStr := func(name string) uint32 {
		if offset, ok := shNameOffsets[name]; ok {
			return offset
		}
		offset := uint32(len(shstrtab))
		shstrtab += name + "\x00"
		shNameOffsets[name] = offset
		return offset
	}

	// Helper to find the end of the last PT_LOAD segment (file size)
	var maxFileOffset uint64 = 0
	for _, phdr := range phdrs {
		if phdr.Type == PT_LOAD {
			end := phdr.Offset + phdr.Filesz
			if end > maxFileOffset {
				maxFileOffset = end
			}
		}
	}

	// Helper to add a section
	addSection := func(name string, sType uint32, flags uint64, addr, size, align, entsize uint64) {
		if size == 0 && sType != SHT_NULL {
			return // Skip empty sections unless it's the null section
		}
		sections = append(sections, SectionInfo{
			Name:      name,
			Type:      sType,
			Flags:     flags,
			Addr:      addr,
			Offset:    addr, // For dumped SO, offset is usually Vaddr
			Size:      size,
			Addralign: align,
			Entsize:   entsize,
		})
	}

	// --- Section Reconstruction Logic ---

	// Add .dynstr
	if dynMap[DT_STRTAB] != 0 && dynMap[DT_STRSZ] != 0 {
		addSection(".dynstr", SHT_STRTAB, SHF_ALLOC, dynMap[DT_STRTAB], dynMap[DT_STRSZ], 1, 0)
	}

	// Add .dynsym
	if dynMap[DT_SYMTAB] != 0 && dynMap[DT_SYMENT] != 0 {
		// We need to estimate the size of the symbol table.
		// For now, we'll use a heuristic: (DT_STRSZ / 10) * DT_SYMENT
		// This is a rough estimate, but better than a fixed size.
		symtabSize := (dynMap[DT_STRSZ] / 10) * dynMap[DT_SYMENT]
		if symtabSize == 0 {
			symtabSize = 0x1000 // Default if estimate is zero
		}
		addSection(".dynsym", SHT_DYNSYM, SHF_ALLOC, dynMap[DT_SYMTAB], symtabSize, 8, dynMap[DT_SYMENT])
	}

	// Add .gnu.hash
	if dynMap[DT_GNU_HASH] != 0 {
		// Size is complex to calculate, use a placeholder size.
		addSection(".gnu.hash", SHT_GNU_HASH, SHF_ALLOC, dynMap[DT_GNU_HASH], 0x1000, 8, 4)
	}

	// Add .dynamic
	addSection(".dynamic", SHT_DYNAMIC, SHF_ALLOC|SHF_WRITE, dynamicPhdr.Vaddr, dynamicPhdr.Memsz, dynamicPhdr.Align, 16)

	// Add .rela.dyn
	if dynMap[DT_RELA] != 0 && dynMap[DT_RELASZ] != 0 {
		addSection(".rela.dyn", SHT_RELA, SHF_ALLOC, dynMap[DT_RELA], dynMap[DT_RELASZ], 8, 24)
	}

	// Add .rela.plt
	if dynMap[DT_JMPREL] != 0 && dynMap[DT_PLTRELSZ] != 0 {
		addSection(".rela.plt", SHT_RELA, SHF_ALLOC|SHF_INFO_LINK, dynMap[DT_JMPREL], dynMap[DT_PLTRELSZ], 8, 24)
	}

	// Add .init_array
	if dynMap[DT_INIT_ARRAY] != 0 && dynMap[DT_INIT_ARRAYSZ] != 0 {
		addSection(".init_array", SHT_INIT_ARRAY, SHF_ALLOC|SHF_WRITE, dynMap[DT_INIT_ARRAY], dynMap[DT_INIT_ARRAYSZ], 8, 8)
	}

	// Add .fini_array
	if dynMap[DT_FINI_ARRAY] != 0 && dynMap[DT_FINI_ARRAYSZ] != 0 {
		addSection(".fini_array", SHT_FINI_ARRAY, SHF_ALLOC|SHF_WRITE, dynMap[DT_FINI_ARRAY], dynMap[DT_FINI_ARRAYSZ], 8, 8)
	}

	// --- Deduce Missing Sections from PHT and Dynamic Pointers ---

	// Find the executable segment (R E) and the writable segment (RW)
	var execPhdr *ProgramHeader
	var rwPhdr *ProgramHeader
	for _, phdr := range phdrs {
		if phdr.Type == PT_LOAD {
			if (phdr.Flags&SHF_EXECINSTR) != 0 && (phdr.Flags&SHF_WRITE) == 0 {
				execPhdr = &phdr
			}
			if (phdr.Flags & SHF_WRITE) != 0 {
				rwPhdr = &phdr
			}
		}
	}

	// 1. Add .text (from executable segment)
	if execPhdr != nil {
		// .text is the executable part of the first LOAD segment.
		// We approximate its size by finding the end of the last known section in the executable segment.
		// For simplicity, we use the entire executable segment's file size for now.
		addSection(".text", SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR, execPhdr.Vaddr, execPhdr.Filesz, 16, 0)
	}

	// 2. Add .got (if not covered by dynamic pointers)
	if dynMap[DT_PLTGOT] != 0 {
		// .got starts at DT_PLTGOT.
		// The size is estimated by the number of PLT relocations * 8 bytes/entry + 3 reserved entries.
		pltRelocCount := dynMap[DT_PLTRELSZ] / 24 // 24 bytes per Elf64_Rela
		gotSize := (pltRelocCount + 3) * 8
		addSection(".got", SHT_PROGBITS, SHF_ALLOC|SHF_WRITE, dynMap[DT_PLTGOT], gotSize, 8, 8)
	}

	// 3. Add .bss (from writable segment)
	if rwPhdr != nil {
		// BSS starts at the end of the file content (Filesz) and extends to Memsz.
		bssStart := rwPhdr.Vaddr + rwPhdr.Filesz
		bssSize := rwPhdr.Memsz - rwPhdr.Filesz
		if bssSize > 0 {
			addSection(".bss", SHT_NOBITS, SHF_ALLOC|SHF_WRITE, bssStart, bssSize, 16, 0)
		}
	}

	// Add .shstrtab (Section Header String Table)
	shstrtabSectionIndex := uint32(len(sections))
	sections = append(sections, SectionInfo{
		Name:      ".shstrtab",
		Type:      SHT_STRTAB,
		Addralign: 1,
	})

	// 3. Fix Links and Names
	nameToIndex := make(map[string]uint32)
	for i := range sections {
		if sections[i].Name != "" {
			nameToIndex[sections[i].Name] = uint32(i)
			// Add string to shstrtab to populate shNameOffsets map
			addShStr(sections[i].Name)
		}
	}

	// Fix sh_link and sh_info
	dynsymIndex := nameToIndex[".dynsym"]
	dynstrIndex := nameToIndex[".dynstr"]
	pltIndex := nameToIndex[".text"] // Placeholder for .plt, using .text index

	for i := range sections {
		sec := &sections[i]

		switch sec.Name {
		case ".dynsym":
			sec.Link = dynstrIndex
			sec.Info = 1
		case ".gnu.hash":
			sec.Link = dynsymIndex
		case ".dynamic":
			sec.Link = dynstrIndex
		case ".rela.dyn":
			sec.Link = dynsymIndex
		case ".rela.plt":
			sec.Link = dynsymIndex
			sec.Info = pltIndex
		}
	}

	// 4. Finalize .shstrtab section
	shstrtabSection := &sections[shstrtabSectionIndex]
	shstrtabSection.Size = uint64(len(shstrtab))
	shstrtabSection.Offset = maxFileOffset // Place at the end of the file content

	// 5. Build and Write SHT
	shdrTableOffset := shstrtabSection.Offset + shstrtabSection.Size
	shdrTableSize := uint64(len(sections)) * uint64(binary.Size(SectionHeader{}))

	// Ensure file is large enough for SHT
	if err := os.Truncate(filePath, int64(shdrTableOffset+shdrTableSize)); err != nil {
		return fmt.Errorf("failed to truncate file for SHT: %w", err)
	}

	if _, err := file.Seek(int64(shdrTableOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to SHT offset 0x%x: %w", shdrTableOffset, err)
	}

	// Write SHT
	for i := range sections {
		sec := &sections[i]
		shdr := SectionHeader{
			Name:      shNameOffsets[sec.Name], // Use the calculated offset from the map
			Type:      sec.Type,
			Flags:     sec.Flags,
			Addr:      sec.Addr,
			Offset:    sec.Offset,
			Size:      sec.Size,
			Link:      sec.Link,
			Info:      sec.Info,
			Addralign: sec.Addralign,
			Entsize:   sec.Entsize,
		}
		// The .shstrtab section header itself must have its Name field set to its own offset in the string table.
		if uint32(i) == shstrtabSectionIndex {
			shdr.Name = shNameOffsets[".shstrtab"]
		}

		if err := binary.Write(file, binary.LittleEndian, shdr); err != nil {
			return fmt.Errorf("failed to write section header %s: %w", sec.Name, err)
		}
	}

	// 6. Write .shstrtab
	if _, err := file.Seek(int64(shstrtabSection.Offset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to .shstrtab offset 0x%x: %w", shstrtabSection.Offset, err)
	}
	if _, err := file.Write([]byte(shstrtab)); err != nil {
		return fmt.Errorf("failed to write .shstrtab: %w", err)
	}

	// 7. Update ELF Header
	header.ShdrOffset = shdrTableOffset
	header.Shentsize = uint16(binary.Size(SectionHeader{}))
	header.Shnum = uint16(len(sections))
	header.Shstrndx = uint16(shstrtabSectionIndex)

	return nil
}

// fixRelocations reads the relocation tables and fixes the pointers they reference.
func fixRelocations(file *os.File, phdrs []ProgramHeader, baseAddr uint64) error {
	var dynamicPhdr *ProgramHeader
	for i := range phdrs {
		if phdrs[i].Type == PT_DYNAMIC {
			dynamicPhdr = &phdrs[i]
			break
		}
	}

	if dynamicPhdr == nil {
		return nil
	}

	// Read the fixed dynamic section to get relocation table info
	entryCount := dynamicPhdr.Memsz / 16
	dynamicEntries := make([]DynamicEntry, entryCount)
	if _, err := file.Seek(int64(dynamicPhdr.Offset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to dynamic section for reading: %w", err)
	}
	if err := binary.Read(file, binary.LittleEndian, &dynamicEntries); err != nil {
		return fmt.Errorf("failed to read dynamic section for relocation info: %w", err)
	}

	var relaOffset, relaSize, jmprelOffset, jmprelSize uint64
	for _, entry := range dynamicEntries {
		switch entry.Tag {
		case DT_RELA:
			relaOffset = entry.Val
		case DT_RELASZ:
			relaSize = entry.Val
		case DT_JMPREL:
			jmprelOffset = entry.Val
		case DT_PLTRELSZ:
			jmprelSize = entry.Val
		}
	}

	// Helper function to process a single relocation table
	processTable := func(offset, size uint64) error {
		if size == 0 {
			return nil
		}
		if size%uint64(binary.Size(RelocationEntry{})) != 0 {
			return fmt.Errorf("relocation table size 0x%x is not a multiple of entry size 0x%x", size, binary.Size(RelocationEntry{}))
		}

		numEntries := size / uint64(binary.Size(RelocationEntry{}))
		relocations := make([]RelocationEntry, numEntries)

		// Read the relocation table
		if _, err := file.Seek(int64(offset), io.SeekStart); err != nil {
			return fmt.Errorf("failed to seek to relocation table at 0x%x: %w", offset, err)
		}
		if err := binary.Read(file, binary.LittleEndian, &relocations); err != nil {
			return fmt.Errorf("failed to read relocation table at 0x%x: %w", offset, err)
		}

		// Fix each relocation entry
		for i := range relocations {
			rel := &relocations[i]
			relType := rel.Info & 0xFFFFFFFF // Lower 32 bits is the type

			// Only fix R_AARCH64_RELATIVE relocations
			if relType == R_AARCH64_RELATIVE {
				// The pointer at rel.Offset is a runtime address.
				// We need to read the pointer, subtract the baseAddr, and write it back.

				// 1. Read the pointer value at rel.Offset
				var pointerVal uint64
				if _, err := file.Seek(int64(rel.Offset), io.SeekStart); err != nil {
					return fmt.Errorf("failed to seek to relocation target 0x%x: %w", rel.Offset, err)
				}
				if err := binary.Read(file, binary.LittleEndian, &pointerVal); err != nil {
					return fmt.Errorf("failed to read relocation target at 0x%x: %w", rel.Offset, err)
				}

				// 2. Fix the pointer: pointerVal = pointerVal - baseAddr
				if pointerVal < baseAddr {
					// This should not happen for a runtime address, but check for robustness
					// We will assume it is a runtime address and fix it.
				}
				fixedPointerVal := pointerVal - baseAddr

				// 3. Write the fixed pointer back
				if _, err := file.Seek(int64(rel.Offset), io.SeekStart); err != nil {
					return fmt.Errorf("failed to seek to relocation target 0x%x for writing: %w", rel.Offset, err)
				}
				if err := binary.Write(file, binary.LittleEndian, fixedPointerVal); err != nil {
					return fmt.Errorf("failed to write fixed relocation target at 0x%x: %w", rel.Offset, err)
				}
			}
		}

		return nil
	}

	// Process DT_RELA and DT_JMPREL tables
	if err := processTable(relaOffset, relaSize); err != nil {
		return fmt.Errorf("DT_RELA fix failed: %w", err)
	}
	if err := processTable(jmprelOffset, jmprelSize); err != nil {
		return fmt.Errorf("DT_JMPREL fix failed: %w", err)
	}

	return nil
}

// fixDynamicSection reads the dynamic section, fixes runtime pointers, and writes it back.
func fixDynamicSection(file *os.File, phdrs []ProgramHeader, baseAddr uint64) error {
	var dynamicPhdr *ProgramHeader
	for i := range phdrs {
		if phdrs[i].Type == PT_DYNAMIC {
			dynamicPhdr = &phdrs[i]
			break
		}
	}

	if dynamicPhdr == nil {
		// Not all SOs have a dynamic section (e.g., static linking), so this is not an error.
		return nil
	}

	// Calculate the number of entries. Memsz is the size of the dynamic array.
	entryCount := dynamicPhdr.Memsz / 16 // sizeof(Elf64_Dyn) is 16 bytes

	if entryCount == 0 {
		return fmt.Errorf("dynamic section has zero size")
	}

	// Read the dynamic section content
	dynamicEntries := make([]DynamicEntry, entryCount)

	// Seek to the file offset of the dynamic section
	if _, err := file.Seek(int64(dynamicPhdr.Offset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to dynamic section: %w", err)
	}

	if err := binary.Read(file, binary.LittleEndian, &dynamicEntries); err != nil {
		return fmt.Errorf("failed to read dynamic section: %w", err)
	}

	// Fix pointers in the dynamic section
	for i := range dynamicEntries {
		entry := &dynamicEntries[i]

		// Only fix entries that are pointers (DT_PTR tags)
		// For a dumped SO, any address-related tag needs to be converted from runtime to relative.
		switch entry.Tag {
		case DT_PLTGOT, DT_HASH, DT_GNU_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_JMPREL, DT_INIT_ARRAY, DT_FINI_ARRAY:
			// Check if the pointer is a runtime address (i.e., greater than the base address)
			if entry.Val >= baseAddr {
				entry.Val -= baseAddr
			}
		case DT_PLTRELSZ, DT_RELASZ, DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ:
			// Size tags are values, not pointers, so no conversion needed.
		case DT_NULL:
			// End of dynamic section, stop processing.
			break
		}
	}

	// Rewrite the fixed dynamic section back to the file
	if _, err := file.Seek(int64(dynamicPhdr.Offset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to dynamic section for writing: %w", err)
	}
	if err := binary.Write(file, binary.LittleEndian, dynamicEntries); err != nil {
		return fmt.Errorf("failed to write fixed dynamic section: %w", err)
	}

	return nil
}

// fixProgramHeaders implements the core logic to fix the program headers.
func fixProgramHeaders(file *os.File, header *ELFHeader, phdrs []ProgramHeader, baseAddr uint64) error {
	// The baseAddr is the runtime address where the SO was loaded.
	// We use it to determine if the Vaddr is a runtime address or a relative address.
	// A typical relative Vaddr is small (e.g., < 0x1000000).

	isRuntimeAddr := func(addr uint64) bool {
		// If the address is larger than a typical relative offset (e.g., 1GB),
		// it's probably a runtime address.
		return addr > 0x100000000
	}

	// 1. Determine if the file contains runtime addresses.
	// We check the first PT_LOAD segment's Vaddr.
	var firstLoadVaddr uint64 = 0
	for i := range phdrs {
		if phdrs[i].Type == PT_LOAD {
			firstLoadVaddr = phdrs[i].Vaddr
			break
		}
	}

	needsConversion := isRuntimeAddr(firstLoadVaddr)

	// 2. Apply fixes
	for i := range phdrs {
		phdr := &phdrs[i]

		if phdr.Type == PT_LOAD {
			// Normalization: For a memory dump, the file size is often the memory size.
			phdr.Filesz = phdr.Memsz
			phdr.Paddr = phdr.Vaddr
			phdr.Offset = phdr.Vaddr

			if needsConversion {
				// Convert runtime Vaddr to file-relative Vaddr
				if phdr.Vaddr < baseAddr {
					return fmt.Errorf("PT_LOAD segment Vaddr 0x%x is less than base address 0x%x", phdr.Vaddr, baseAddr)
				}
				relativeVaddr := phdr.Vaddr - baseAddr

				// Apply the relative Vaddr to all address/offset fields
				phdr.Offset = relativeVaddr
				phdr.Vaddr = relativeVaddr
				phdr.Paddr = relativeVaddr
			} else {
				// If already relative, ensure Offset/Vaddr/Paddr consistency for normalization
				phdr.Offset = phdr.Vaddr
				phdr.Paddr = phdr.Vaddr
			}
		}

		// Fix PT_PHDR: it points to the PHT itself.
		if phdr.Type == PT_PHDR {
			// The PHT is at header.PhdrOffset in the file.
			// The Vaddr/Paddr/Offset should all point to the file offset.
			phdr.Vaddr = header.PhdrOffset
			phdr.Paddr = header.PhdrOffset
			phdr.Offset = header.PhdrOffset
		}

		// Fix GNU-specific headers: PT_GNU_EH_FRAME, PT_GNU_RELRO, PT_GNU_STACK
		if phdr.Type == PT_GNU_EH_FRAME || phdr.Type == PT_GNU_RELRO || phdr.Type == PT_GNU_STACK {
			if needsConversion {
				if phdr.Vaddr < baseAddr {
					return fmt.Errorf("GNU segment Vaddr 0x%x is less than base address 0x%x", phdr.Vaddr, baseAddr)
				}
				relativeVaddr := phdr.Vaddr - baseAddr
				phdr.Offset = relativeVaddr
				phdr.Vaddr = relativeVaddr
				phdr.Paddr = relativeVaddr
			} else {
				// If already relative, ensure Offset/Paddr consistency
				phdr.Offset = phdr.Vaddr
				phdr.Paddr = phdr.Vaddr
			}
			// Also ensure Filesz = Memsz for consistency, especially for PT_GNU_RELRO
			if phdr.Type == PT_GNU_RELRO {
				phdr.Filesz = phdr.Memsz
			}
		}

		// Fix PT_DYNAMIC: it points to the dynamic section.
		if phdr.Type == PT_DYNAMIC {
			if needsConversion {
				if phdr.Vaddr < baseAddr {
					return fmt.Errorf("PT_DYNAMIC segment Vaddr 0x%x is less than base address 0x%x", phdr.Vaddr, baseAddr)
				}
				relativeVaddr := phdr.Vaddr - baseAddr
				phdr.Offset = relativeVaddr
				phdr.Vaddr = relativeVaddr
				phdr.Paddr = relativeVaddr
			} else {
				// If already relative, ensure Offset/Paddr consistency
				phdr.Offset = phdr.Vaddr
				phdr.Paddr = phdr.Vaddr
			}
		}
	}

	// Update ELF header fields to reflect the fixed PHT
	header.Type = ET_DYN
	header.Machine = EM_AARCH64

	return nil
}
