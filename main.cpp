#include <iostream>

extern "C" {
    bool main_loop(int argc, char *argv[]);
}

int main(int argc, char** argv) {
    if (main_loop(argc, argv)) {
        return 0;
    } else {
        return 1;
    }
}
