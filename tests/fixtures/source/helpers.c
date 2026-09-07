int clamp(int value) {
    if (value < 0) return 0;
    return value;
}

int result(void) {
    return clamp(7);
}
