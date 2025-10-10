build:
	@go mod download
	@CGO_ENABLED=1 GO111MODULE=on GOOS=linux go build -o crm main.go
	@cp -rf crm /usr/local/bin/crm
	@cp -rf crm.service /etc/systemd/system/crm.service
	@systemctl enable crm
	@systemctl start crm
