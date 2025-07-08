migrate-create:
	migrate create -ext sql -dir migrations -seq $(name)

swag-init:
	swag init -g ./cmd/main/main.go

run:
	go run ./cmd/main/main.go