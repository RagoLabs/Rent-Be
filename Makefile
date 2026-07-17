sqlc:		
	sqlc generate
	
server:
	go run ./cmd/api

test:
	go test -v -count=1 ./...
	
.PHONY: sqlc server test 
