typedef int (*Callback)(int);

__attribute__((noinline)) int plus_one(int value) {
    return value + 1;
}

Callback callback_slot = plus_one;

__attribute__((noinline)) int call_callback(int value) {
    return callback_slot(value);
}

__attribute__((noinline)) int entry(void) {
    return call_callback(3);
}
