#include <stdio.h>
__attribute__((weak)) void foo() {
    printf("weak foo\n");
}
