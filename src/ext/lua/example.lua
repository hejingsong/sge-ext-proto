local proto = require "libsgeproto.core"
local proto_file = "../../../example/example.proto"
local protocol = proto.parse_file(proto_file)
proto.debug(protocol)
