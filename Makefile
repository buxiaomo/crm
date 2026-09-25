build:
	@go mod download
	@CGO_ENABLED=0 GO111MODULE=on GOOS=linux GOARCH=amd64 go build -o crm main.go
	@cp -rf crm /usr/local/bin/crm
	@cp -rf crm.service /etc/systemd/system/crm.service
	@cp -rf config.yaml /usr/local/etc/crm.yaml
	@systemctl enable crm
	@systemctl restart crm
