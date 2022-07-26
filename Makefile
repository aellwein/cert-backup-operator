rwildcard  = $(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))
GOFILES    := $(call rwildcard,./,*.go)
LDFLAGS    ?= -w -extldflags "-static"

build:	build/cert-backup-operator

build/cert-backup-operator:	$(GOFILES)
	go build -o $@ -ldflags "$(LDFLAGS)" ./cmd/...

build/cert-backup-operator.linux:	$(GOFILES)
	GOOS=linux GOARCH=amd64 go build -o $@ -ldflags "$(LDFLAGS)" ./cmd/...

image:	build/cert-backup-operator.linux
	docker build -t elvino76/cert-backup-operator:0.1.0 . 

clean:
	$(RM) -r build

.PHONY:	clean image build