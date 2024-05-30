package bimap

type Bimap[K, V comparable] struct {
	forward map[K]V
	reverse map[V]K
}

func New[K, V comparable]() Bimap[K, V] {
	bm := Bimap[K, V]{}
	bm.initialize()

	return bm
}

func Of[K, V comparable](m map[K]V) Bimap[K, V] {
	bm := New[K, V]()
	for k, v := range m {
		bm.Add(k, v)
	}

	return bm
}

func (b *Bimap[K, V]) Size() int {
	return len(b.forward)
}

func (b *Bimap[K, V]) Add(k K, v V) {
	if oldValue, ok := b.forward[k]; ok {
		delete(b.reverse, oldValue)
	}

	if oldValue, ok := b.reverse[v]; ok {
		delete(b.forward, oldValue)
	}

	b.initialize() // Initialize if needed

	b.forward[k] = v
	b.reverse[v] = k
}

func (b *Bimap[K, V]) GetForward(k K) (V, bool) {
	element, ok := b.forward[k]

	return element, ok
}

func (b *Bimap[K, V]) GetBackwards(v V) (K, bool) {
	element, ok := b.reverse[v]

	return element, ok
}

func (b *Bimap[K, V]) RemoveForward(k K) {
	if v, ok := b.forward[k]; ok {
		delete(b.forward, k)
		delete(b.reverse, v)
	}
}

func (b *Bimap[K, V]) RemoveBackwards(v V) {
	if k, ok := b.reverse[v]; ok {
		delete(b.reverse, v)
		delete(b.forward, k)
	}
}

func (b *Bimap[K, V]) Each(f func(k K, v V)) {
	for k, v := range b.forward {
		f(k, v)
	}
}

func (b *Bimap[K, V]) Clear() {
	if !b.IsInitialized() {
		return
	}

	clear(b.forward)
	clear(b.reverse)
}

func (b *Bimap[K, V]) IsInitialized() bool {
	return b.forward != nil
}

func (b *Bimap[K, V]) ForwardMap() map[K]V {
	result := make(map[K]V)
	for k, v := range b.forward {
		result[k] = v
	}

	return result
}

func (b *Bimap[K, V]) ReverseMap() map[V]K {
	result := make(map[V]K)
	for k, v := range b.reverse {
		result[k] = v
	}

	return result
}

func (b *Bimap[K, V]) initialize() {
	if !b.IsInitialized() {
		b.forward = make(map[K]V)
		b.reverse = make(map[V]K)
	}
}
