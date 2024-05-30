package bimap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

func TestBimap_Add(t *testing.T) {
	t.Run("Add Single Element", func(t *testing.T) {
		b := New[int, int]()
		b.Add(1, 2)

		assert.Len(t, b.forward, 1)
		assert.Len(t, b.reverse, 1)

		assert.Equal(t, 2, b.forward[1])
		assert.Equal(t, 1, b.reverse[2])
	})

	t.Run("Add multiple elements", func(t *testing.T) {
		b := New[int, int]()
		b.Add(1, 2)
		b.Add(2, 3)

		assert.Len(t, b.forward, 2)
		assert.Len(t, b.reverse, 2)

		assert.Equal(t, 2, b.forward[1])
		assert.Equal(t, 1, b.reverse[2])
		assert.Equal(t, 3, b.forward[2])
		assert.Equal(t, 2, b.reverse[3])
	})

	t.Run("Add Duplicated Forward Element", func(t *testing.T) {
		b := New[int, int]()
		b.Add(1, 2)
		b.Add(1, 4)

		assert.Len(t, b.forward, 1)
		assert.Len(t, b.reverse, 1)

		assert.Equal(t, 4, b.forward[1])
		assert.Equal(t, 1, b.reverse[4])
	})

	t.Run("Add Duplicated Backward Element", func(t *testing.T) {
		b := New[int, int]()
		b.Add(1, 2)
		b.Add(4, 2)

		assert.Len(t, b.forward, 1)
		assert.Len(t, b.reverse, 1)

		assert.Equal(t, 2, b.forward[4])
		assert.Equal(t, 4, b.reverse[2])
	})
}

func TestBimap_Clear(t *testing.T) {
	// Given
	m := map[int]int{1: 2, 2: 3, 3: 4}
	bimap := Of(m)

	// When
	bimap.Clear()

	// Then
	assert.Len(t, bimap.forward, 0)
	assert.Len(t, bimap.reverse, 0)
	assert.NotNil(t, bimap.forward)
	assert.NotNil(t, bimap.reverse)
}

func TestBimap_Each(t *testing.T) {
	// Given
	m := map[int]int{1: 2, 2: 3, 3: 4}
	bimap := Of(m)

	newMap := make(map[int]int)

	// When
	bimap.Each(func(k int, v int) {
		require.NotContains(t, maps.Keys(newMap), k)

		newMap[k] = v
	})

	// Then
	assert.Equal(t, m, newMap)
}

func TestBimap_GetBackwards(t *testing.T) {
	m := map[int]string{1: "a", 2: "b", 3: "c"}
	bimap := Of(m)

	t.Run("Element exists", func(t *testing.T) {
		e, ok := bimap.GetBackwards("a")

		assert.True(t, ok)
		assert.Equal(t, 1, e)
	})

	t.Run("Element does not exist", func(t *testing.T) {
		e, ok := bimap.GetBackwards("d")

		assert.False(t, ok)
		assert.Zero(t, e)
	})
}

func TestBimap_GetForward(t *testing.T) {
	m := map[int]string{1: "a", 2: "b", 3: "c"}
	bimap := Of(m)

	t.Run("Element exists", func(t *testing.T) {
		e, ok := bimap.GetForward(2)

		assert.True(t, ok)
		assert.Equal(t, "b", e)
	})

	t.Run("Element does not exist", func(t *testing.T) {
		e, ok := bimap.GetForward(6)

		assert.False(t, ok)
		assert.Zero(t, e)
	})
}

func TestBimap_RemoveBackwards(t *testing.T) {
	t.Run("Remove existing element", func(t *testing.T) {
		m := map[int]string{1: "a", 2: "b", 3: "c"}
		bimap := Of(m)

		bimap.RemoveBackwards("a")

		assert.Len(t, bimap.forward, 2)
		assert.Len(t, bimap.reverse, 2)

		_, ok := bimap.GetBackwards("a")
		assert.False(t, ok)
	})

	t.Run("Remove non-existing element", func(t *testing.T) {
		m := map[int]string{1: "a", 2: "b", 3: "c"}
		bimap := Of(m)

		bimap.RemoveBackwards("d")

		assert.Equal(t, m, bimap.forward)
	})
}

func TestBimap_RemoveForward(t *testing.T) {
	t.Run("Remove existing element", func(t *testing.T) {
		m := map[int]string{1: "a", 2: "b", 3: "c"}
		bimap := Of(m)

		bimap.RemoveForward(2)

		assert.Len(t, bimap.forward, 2)
		assert.Len(t, bimap.reverse, 2)

		_, ok := bimap.GetForward(2)
		assert.False(t, ok)
	})

	t.Run("Remove non-existing element", func(t *testing.T) {
		m := map[int]string{1: "a", 2: "b", 3: "c"}
		bimap := Of(m)

		bimap.RemoveForward(6)

		assert.Equal(t, m, bimap.forward)
	})
}

func TestOf(t *testing.T) {
	// Given
	m := map[int]string{1: "a", 2: "b", 3: "c"}

	// When
	bimap := Of(m)

	// Then
	assert.Equal(t, m, bimap.forward)
	assert.Equal(t, map[string]int{"a": 1, "b": 2, "c": 3}, bimap.reverse)
}

func TestBimap_IsInitialized(t *testing.T) {
	t.Run("Uninitialized bimap", func(t *testing.T) {
		var b Bimap[int, string]

		assert.False(t, b.IsInitialized())
	})

	t.Run("Initialized bimap", func(t *testing.T) {
		b := New[int, string]()

		assert.True(t, b.IsInitialized())
	})

	t.Run("Initialized after adding an element", func(t *testing.T) {
		// Given
		var b Bimap[int, string]

		require.False(t, b.IsInitialized())

		// When
		b.Add(1, "a")

		// Then
		assert.True(t, b.IsInitialized())
	})
}
