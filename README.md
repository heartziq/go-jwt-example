## JWT implementation in go
1. clone
```sh
git clone https://github.com/heartziq/go-jwt-example.git
```

2. create secret key (to jwt sign)
```sh
cd go-jwt-example
./genSecret.sh
```

3. start server
```sh
go run main.go
```

4. run client
```sh
cd client
go run main.go
```