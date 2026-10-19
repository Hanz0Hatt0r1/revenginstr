struct Value { int value; };
__attribute__((noinline)) struct Value *source(struct Value *p, int delta) {
    p->value += delta;
    return p;
}
__attribute__((noinline)) struct Value *forward(struct Value *p, int delta) {
    return source(p, delta);
}
