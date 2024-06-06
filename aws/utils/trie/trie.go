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

func FromMap[T any](keySeparator string, m map[string]T) *Trie[T] {
	t := New[T](keySeparator)

	for k, v := range m {
		t.Insert(k, v)
	}

	return t
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

// Get returns the value for a given key
func (t *Trie[T]) Get(key string) (T, bool) {
	var t0 T

	keyParts := strings.Split(key, t.sep)

	node, found := t.root.GetNode(keyParts)

	if !found || node.leaf == nil {
		return t0, false
	}

	return node.leaf.value, true
}

// GetClosest returns the value for the closest key
func (t *Trie[T]) GetClosest(key string) (string, T) {
	var t0 T

	keyParts := strings.Split(key, t.sep)

	node := t.root.GetClosestNode(keyParts)

	if node.leaf == nil {
		return "", t0
	}

	return node.leaf.key, node.leaf.value
}

func (t *Trie[T]) Size() int {
	if t.root == nil {
		return 0
	}

	return t.root.Count()
}

func (t *Trie[T]) Iterate(f func(key string, value T)) {
	if t.root != nil {
		t.root.Iterate(f)
	}
}

func (t *Trie[T]) Equal(other *Trie[T], equalFn func(a T, b T) bool) bool {
	if t.root == nil {
		return other.root == nil
	}

	if other.root == nil {
		return false
	}

	return t.root.Equal(other.root, equalFn)
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

func (n *Node[T]) GetNode(keyParts []string) (*Node[T], bool) {
	if len(keyParts) == 0 {
		return n, true
	}

	if n.edges == nil {
		return nil, false
	}

	e, ok := n.edges[keyParts[0]]
	if !ok {
		return nil, false
	}

	return e.node.GetNode(keyParts[1:])
}

func (n *Node[T]) GetClosestNode(keyParts []string) *Node[T] {
	if len(keyParts) == 0 {
		return n
	}

	if n.edges == nil {
		return n
	}

	e, ok := n.edges[keyParts[0]]
	if !ok {
		return n
	}

	return e.node.GetClosestNode(keyParts[1:])
}

func (n *Node[T]) Iterate(f func(key string, value T)) {
	if n.leaf != nil {
		f(n.leaf.key, n.leaf.value)
	}

	for _, e := range n.edges {
		e.node.Iterate(f)
	}
}

func (n *Node[T]) Equal(other *Node[T], equalFn func(a T, b T) bool) bool {
	if n.leaf != nil {
		if other.leaf == nil {
			return false
		}

		if !equalFn(n.leaf.value, other.leaf.value) {
			return false
		}
	}

	if len(n.edges) != len(other.edges) {
		return false
	}

	for k, e := range n.edges {
		otherE, ok := other.edges[k]
		if !ok || !e.node.Equal(otherE.node, equalFn) {
			return false
		}
	}

	return true
}
