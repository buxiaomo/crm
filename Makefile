build:
	@go build -o crm && ./crm -c ./crm.yaml 
	@cp -rf crm /usr/local/bin/crm
	@cp -rf crm.service /etc/systemd/system/crm.service
	@systemctl enable crm
	@systemctl start crm
