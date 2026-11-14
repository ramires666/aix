//go:build !windows

package main

import "os"

func readStudioOperationFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
