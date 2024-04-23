import SgeProto

filename = "../../../example/example.proto"

base = {
    "name": "SgeProto"
}
person = {
    "base_info": {
        "name": "SgeProto"
    }
}
person_list = {
    "base_info": [
        {"name": "SgeProto"}
    ]
}
optional = {
    "age": 1,
    "name": "aa"
}
optional1 = {
}

optional_list = {
    "list": [
        {"age": 1, "name": "111"},
        {"age": 2, "name": "222"}
    ]
}
optional_list1 = {
    "list": [
        {"age": 1},
        {"name": "33"}
    ]
}
optional_list_list = {
    "list": [
        {"list": [
            {"age": 1, "name": "111"},
            {"age": 2, "name": "222"}
        ]},
        {"list": [
            {"age": 3, "name": "333"},
            {"age": 4, "name": "444"}
        ]},
    ]
}
optional_list_list1 = {
    "list": [
        {"list": [
            {},
            {}
        ]},
        {"list": [
            {"age": 3},
            {"name": "444"}
        ]},
    ]
}

protocol = SgeProto.parseFile(filename)
protocol.debug()

s = protocol.encode("Base", base)
data = protocol.decode(s)
print(data)

s = protocol.encode("Person", person)
data = protocol.decode(s)
print(data)

s = protocol.encode("PersonList", person_list)
data = protocol.decode(s)
print(data)

s = protocol.encode("Optional", optional)
data = protocol.decode(s)
print(data)

s = protocol.encode("Optional", optional1)
data = protocol.decode(s)
print(data)

s = protocol.encode("OptionalList", optional_list)
data = protocol.decode(s)
print(data)

s = protocol.encode("OptionalList", optional_list1)
data = protocol.decode(s)
print(data)

s = protocol.encode("OptionalListList", optional_list_list)
data = protocol.decode(s)
print(data)

s = protocol.encode("OptionalListList", optional_list_list1)
data = protocol.decode(s)
print(data)
