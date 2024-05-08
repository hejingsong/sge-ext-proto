# Introduction
A simple serialization tool.

# build
```shell
cmake -B build .
cd build && make
```
This will generate a static link library file: `./build/lib/libsgeextproto.a`

## python3 extension
```shell
cd src/ext/python3
python setup.py install
```

# Example
## Schema file
```
# comment
@include "base.proto"

# define a message
HelloRequest 404 {
    message string required;
}

HelloResponse 405 {
    age integer required;
    reply string required;
}

# define a service
service Example {
  rpc Hello(HelloRequest) -> HelloResponse;
}
```

## use in python3
```python
import SgeProto

protocol = SgeProto.parseFile("/path/to/schema_file")
# print schema
protocol.debug()

hello_request = {
    "message": "Hello World."
}
hello_response = {
    "age": 10,
    "reply": "Hello World."
}

# encode/decode message
bin = protocol.encode("HelloRequest", hello_request)
data = protocol.decode(bin)
print(data)

// encode/decode request/response
s = protocol.encodeRequest("Example", "Hello", hello_request)
data = protocol.decodeService(s)
print(data)

s = protocol.encodeResponse("Example", "Hello", hello_response)
data = protocol.decodeService(s)
print(data)
```
