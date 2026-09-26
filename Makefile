build:
	@go mod download
	@CGO_ENABLED=0 GO111MODULE=on GOOS=linux GOARCH=amd64 go build -o crm main.go

install: build
	@install -D -m 755 crm /usr/local/bin/crm
	@install -D -m 644 crm.service /etc/systemd/system/crm.service
	@install -D -m 644 config.yaml /usr/local/etc/crm.yaml
	@systemctl enable crm
	@systemctl restart crm
