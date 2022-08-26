#include <stdio.h>

int add(int a, int b)
{
    return (a + b);
}

int main()
{
    int p = 10;
    int q = 20;
    printf("p + q = %d\n", add(p, q));
    return 0;
}