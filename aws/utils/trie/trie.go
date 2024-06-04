package trie

type leafNode[T any] struct {
	key   []byte
	value T
}

type edge[T any] struct {
	label byte
	node  *Node[T]
}

type Node[T any] struct {
	leaf  *leafNode[T]
	edges map[byte]edge[T]
}

type Trie[T any] struct {
	root *Node[T]
}

func New[T any]() *Trie[T] {
	return &Trie[T]{}
}

func (t *Trie[T]) Insert(key []byte, value T) {
	if t.root == nil {
		t.root = &Node[T]{}
	}

	n := t.root

	for _, k := range key {
		if n.edges == nil {
			n.edges = make(map[byte]edge[T])
		}

		e, ok := n.edges[k]
		if !ok {
			e = edge[T]{label: k, node: &Node[T]{}}
			n.edges[k] = e
		}

		n = e.node
	}

	n.leaf = &leafNode[T]{key: key, value: value}
}

func (t *Trie[T]) SearchPrefix(key []byte) []T {
	n := t.root

	for _, k := range key {
		if n.edges == nil {
			return nil
		}

		e, ok := n.edges[k]
		if !ok {
			return nil
		}

		n = e.node
	}

	var result []T

	if n.leaf != nil {
		result = append(result, n.leaf.value)
	}

	result = append(result, n.GetAllLeafs()...)

	return result
}

func (t *Trie[T]) Size() int {
	if t.root == nil {
		return 0
	}

	return t.root.Count()
}

func (n *Node[T]) GetAllLeafs() []T {
	var result []T

	n.Iterate(func(_ []byte, value T) {
		result = append(result, value)
	})

	return result
}

func (n *Node[T]) Count() int {
	count := 0

	if n.leaf != nil {
		count++
	}

	for _, e := range n.edges {
		count += e.node.Count()
	}

	return count
}

func (n *Node[T]) Iterate(f func(key []byte, value T)) {
	if n.leaf != nil {
		f(n.leaf.key, n.leaf.value)
	}

	for _, e := range n.edges {
		e.node.Iterate(f)
	}
}
