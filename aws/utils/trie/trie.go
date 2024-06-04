package trie

import "strings"

type leafNode[T any] struct {
	key   string
	value T
}

type edge[T any] struct {
	label string
	node  *Node[T]
}

type Node[T any] struct {
	leaf  *leafNode[T]
	edges map[string]edge[T]
}

// Trie is a simplified version of a Radix tree (https://en.wikipedia.org/wiki/Radix_tree#:~:text=In%20computer%20science%2C%20a%20radix,is%20merged%20with%20its%20parent.)
// Trie can be used to search for objects based on a key prefix
// To improve performance, the key is split by a separator instead of a common characters.
type Trie[T any] struct {
	sep  string
	root *Node[T]
}

// New creates a new (Radix) Trie
func New[T any](keySeparator string) *Trie[T] {
	return &Trie[T]{sep: keySeparator}
}

// Insert a new value with given key
func (t *Trie[T]) Insert(key string, value T) {
	if t.root == nil {
		t.root = &Node[T]{}
	}

	n := t.root

	keyParts := strings.Split(key, t.sep)

	for _, k := range keyParts {
		if n.edges == nil {
			n.edges = make(map[string]edge[T])
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

// SearchPrefix search for all values that within the data structure with a given prefix
// Note that the prefix key will be split by the separator
func (t *Trie[T]) SearchPrefix(key string) []T {
	n := t.root

	keyParts := strings.Split(key, t.sep)

	for _, k := range keyParts {
		if n.edges == nil {
			return nil
		}

		e, ok := n.edges[k]
		if !ok {
			return nil
		}

		n = e.node
	}

	return n.GetAllLeafs()
}

func (t *Trie[T]) Size() int {
	if t.root == nil {
		return 0
	}

	return t.root.Count()
}

func (n *Node[T]) GetAllLeafs() []T {
	var result []T

	n.Iterate(func(_ string, value T) {
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

func (n *Node[T]) Iterate(f func(key string, value T)) {
	if n.leaf != nil {
		f(n.leaf.key, n.leaf.value)
	}

	for _, e := range n.edges {
		e.node.Iterate(f)
	}
}
