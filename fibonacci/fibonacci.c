#include "stdio.h"

int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n-1) + fibonacci(n-2);
}

int main(int argc, char const *argv[])
{
    int x = 0;
    int r = 0;
    int n = x + 6;
    r = fibonacci(n);

    printf("%d\n", r);
    return 0;
}