.PHONY: check

ifeq ($(OS),Windows_NT)
check:
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1
else
check:
	go mod tidy -diff
	go mod verify
	test -z "$$(gofmt -l $$(git ls-files '*.go'))"
	go vet ./...
	go test ./...
	go test -race ./...
	go build ./...
endif
