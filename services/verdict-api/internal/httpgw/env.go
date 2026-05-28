package httpgw

import "os"

// goGetenv — single os.Getenv indirection (kept here so pipeline.go doesn't
// need its own "os" import; helps when stubbing in tests).
func goGetenv(k string) string {
	return os.Getenv(k)
}
