clang++ -O2 -o SoFixer64Static ElfReader.cpp ElfRebuilder.cpp ObElfReader.cpp main.cpp -std=c++14 -static-libstdc++ -lc++
