typedef struct Node {
    int value;
} Node;

__attribute__((noinline)) Node *mystery_mutate(Node *node, int delta) {
    node->value += delta;
    return node;
}

__attribute__((noinline)) int mystery_caller(Node *node) {
    return mystery_mutate(node, 3)->value;
}
