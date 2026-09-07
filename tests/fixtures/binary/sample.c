/* Benign parser fixture. Never a course acceptance sample or vulnerability PoC. */
int helper(int value) { return value + 1; }

#ifdef __ELF__
void _start(void) {
    volatile int answer = helper(41);
    (void)answer;
    __asm__ volatile("mov $60, %%rax; xor %%rdi, %%rdi; syscall" ::: "rax", "rdi");
}
#else
int entry(void) { return helper(41); }
#endif
