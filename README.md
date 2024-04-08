# healthscript

A [DSL](https://en.wikipedia.org/wiki/Domain-specific_language) for healthcheck scripts that compiles to WASM.

## HTTP Examples

```
https://example.com
```

- Makes an HTTP GET request to `https://example.com`
- Will return `true` when all of the following are true
  - `200` status code

```
[User-Agent: my-agent](https://example.com)[X-Powered-By: my-header]
```

- Makes an HTTP GET request to `https://example.com`
  - With the `User-Agent` header set to `my-agent`
- Will return `true` when all of the following are true
  - `200` status code
  - `X-Powered-By` header is `my-header`

```
[Accept: application/json](https://example.com).[1].price == 0.5
```

- Makes an HTTP GET request to `https://example.com`
  - With the `Accept` header set to `application/json`
- Will return `true` when all of the following are true
  - `200` status code
  - The response is valid JSON, and the [jq](https://stedolan.github.io/jq) expression `.[1].price == 0.5` is `true`.

```
[Accept: application/json][Authorization: Bearer $auth](https://example.com)/my.*ue/
```

- Makes an HTTP GET request to `https://example.com`
  - With the `Accept` header set to `application/json`
  - With the `Authorization` header set to `Bearer $auth`, where `$auth` is a named variable which can be passed to the script when run.
- Will return `true` when all of the following are true
  - `200` status code
  - The response content matches the regular expression `/my.*ue/`

```
[POST]<{ "mykey": "myvalue" }>(https://example.com)
```

- Makes an HTTP POST request to `https://example.com`
  - With request body as the JSON object `{ "mykey": "myvalue" }`
- Will return `true` when all of the following are true
  - `200` status code

```
[POST]<aHR0cHM6Ly9naXRodWIuY29tL3Job21idXNnZy9oZWFsdGhzY3JpcHQ=>(https://example.com)
```

- Makes an HTTP POST request to `https://example.com`
  - With request body as the decoded base64 string `aHR0cHM6Ly9naXRodWIuY29tL3Job21idXNnZy9oZWFsdGhzY3JpcHQ=`
- Will return `true` when all of the following are true
  - `200` status code

```
(https://example.com)[404].status == "Not found"
```

- Makes an HTTP GET request to `https://example.com`
- Will return `true` when all of the following are true
  - `404` status code
  - The response is valid JSON, and the [jq](https://stedolan.github.io/jq) expression `.status == "Not found"` is `true`.

```
https://example.com and https://example2.com
```

- Makes HTTP GET requests to `https://example.com` and `https://example2.com`
- Will return `true` when all of the following are true
  - `https://example.com` returns a `200` status code
  - `https://example2.com` returns a `200` status code

## TCP/UDP Examples

```
(tcp://example.com:1337)/.+/
```

- Connects to `example.com` on port `1337`
  - Returns `true` if the response matches the regular expression `/.+/` (if at least 1 byte is returned)

```
(tcp://example.com:1337)/Welcome to/
```

- Connects to `example.com` on port `1337`
  - Returns `true` if the response matches the regular expression `/Welcome to/` (there is a sequence of bytes `Welcome to` anywhere in the response)

```
(tcp://example.com:1337)/^Welcome to/
```

- Connects to `example.com` on port `1337`
  - Returns `true` if the response matches the regular expression `/^Welcome to/` (the response starts with the bytes `Welcome to`)

## Ping Examples

```
ping://example.com
```

- Pings `example.com` and returns `true` if the response is successful.

## DNS Examples

```
dns://1.1.1.1/example.com
```

- Resolves `example.com` using the DNS server `1.1.1.1`
