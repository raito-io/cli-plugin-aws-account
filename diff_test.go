package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
)

func TestDiff(t *testing.T) {
	// The bad one:
	fileName1 := "/Users/dieterwachters/git/raito/cli-examples/raito-io-cli-plugin-aws-account-da-2023-07-20T13-01-21.563352+02-00-8400395.json"
	// The good one:
	fileName2 := "/Users/dieterwachters/git/raito/cli-examples/raito-io-cli-plugin-aws-account-da-2023-07-20T12-46-33.883262+02-00-6063416.json"

	jsonFile1, err := os.Open(fileName1)
	if err != nil {
		fmt.Println(err.Error())
	}
	defer jsonFile1.Close()

	jsonFile2, err := os.Open(fileName2)
	if err != nil {
		fmt.Println(err.Error())
	}
	defer jsonFile2.Close()

	byteValue1, _ := io.ReadAll(jsonFile1)
	byteValue2, _ := io.ReadAll(jsonFile2)

	// We'll unmarshal the JSON into this map
	result1 := []*AP{}
	result2 := []*AP{}

	// Unmarshal the bytes into the map
	json.Unmarshal(byteValue1, &result1)
	json.Unmarshal(byteValue2, &result2)

	map1 := make(map[string]*AP)
	map2 := make(map[string]*AP)

	for _, r1 := range result1 {
		map1[r1.Name] = r1
	}

	for _, r2 := range result2 {
		map2[r2.Name] = r2
	}

	diffMaps(map1, map2)
}

func diffMaps(map1, map2 map[string]*AP) {
	// Check all keys in map1 and whether they're in map2
	for key, value := range map1 {
		if _, ok := map2[key]; !ok {
			fmt.Printf("Key %s is only in the first map: %+v\n", key, value)
		}
	}

	// Check all keys in map2 and whether they're in map1
	for key, value := range map2 {
		if _, ok := map1[key]; !ok {
			fmt.Printf("Key %s is only in the second map: %+v\n", key, value)
		}
	}
}

type AP struct {
	Name string `json:"name"`
	Type string `json:"type"`
}
