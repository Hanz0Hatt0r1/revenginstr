struct Node {
    int value;
};

__attribute__((noinline)) struct Node *sample_add(struct Node *node, int delta) {
    node->value += delta;
    return node;
}
