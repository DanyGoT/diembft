module github.com/DanyGoT/diembft

go 1.27.3

require (
	github.com/relab/gorums v0.14.1-0.20261117141100-a4472733a8cb
	github.com/relab/gorums/benchkit v0.14.1-0.20261117141100-a4472733a8cb
	google.golang.org/grpc v1.85.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	golang.org/x/exp v0.0.0-20261109185158-a52e3aef5920 // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	golang.org/x/tools v0.52.1-0.20261106145633-d407941a339a // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261110000943-09e21b237f2c // indirect
)

tool (
	github.com/relab/gorums/cmd/protoc-gen-gorums
	google.golang.org/protobuf/cmd/protoc-gen-go
)
