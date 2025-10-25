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
	DT_GNU_HASH     = 0x6ffffef5
)

// DynamicEntry represents a 64-bit dynamic section entry (Elf64_Dyn).
type DynamicEntry struct {
	Tag uint64 // Dynamic entry type
	Val uint64 // Value or pointer
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

	// 5. Rewrite the fixed PHT back to the file
	if _, err := file.Seek(int64(header.PhdrOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to program header table for writing: %w", err)
	}
	if err := binary.Write(file, binary.LittleEndian, phdrs); err != nil {
		return fmt.Errorf("failed to write fixed program header table: %w", err)
	}

	// 5. Rewrite the fixed ELF header (in case any fields were modified)
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to ELF header for writing: %w", err)
	}
	if err := binary.Write(file, binary.LittleEndian, &header); err != nil {
		return fmt.Errorf("failed to write fixed ELF header: %w", err)
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
