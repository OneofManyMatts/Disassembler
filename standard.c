#include <stdio.h>

int test();

int test2(){
    return test();//Will blow up after a while
}

int test(){
    return test2();
}

int main()
{
    return test();
}