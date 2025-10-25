package main

import (
	"fmt"
	"os"
	"strconv"

	pkg "github.com/BetterSoFixer/SoFixer64/pkg"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: SoFixer64 <elf_file> <base_address>")
		os.Exit(1)
	}

	filePath := os.Args[1]
	baseAddrStr := os.Args[2]

	// Parse base address. The '0' base allows for "0x" prefix for hex.
	baseAddr, err := strconv.ParseUint(baseAddrStr, 0, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid base address '%s': %v\n", baseAddrStr, err)
		os.Exit(1)
	}

	err = pkg.FixELFHeaders(filePath, baseAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fixing ELF headers: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("ELF headers fixed successfully.")
}
