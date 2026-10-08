/* API 87.1 does not export the compiler's 32-bit popcount helper. */
int __popcountsi2(unsigned int value) {
    unsigned int count = 0;
    while(value != 0U) {
        value &= value - 1U;
        count++;
    }
    return (int)count;
}
