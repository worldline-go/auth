# HTTP example usage

Before to start this example, change settings in the [provider.go](./provider.go) file.

Run the server and before run docs to generate swagger documentation.

```sh
make docs run-server
```

Send a request to the server.

```sh
make run-client
```

## Notes

Before to start this example,  
Add the http://localhost:3000/* in the valid redirect URIs  
Add the http://localhost:3000 in the valid origins  
