local sha384 = {}

local bit = require("bit")
local ffi = require("ffi")

ffi.cdef[[
    typedef unsigned char uint8_t;
    typedef unsigned long uint32_t;
    typedef unsigned long long uint64_t;
    typedef struct SHA384Context {
        uint64_t total[2];
        uint64_t state[8];
        uint8_t buffer[128];
    } SHA384Context;
    void SHA384_Init(SHA384Context* context);
    void SHA384_Update(SHA384Context* context, const void* data, uint32_t len);
    void SHA384_Final(uint8_t digest[48], SHA384Context* context);
]]

local lib
if ffi.os == "Windows" then
    lib = ffi.load("libeay32")
else
    lib = ffi.load("crypto")
end

function sha384.hash(str)
    local context = ffi.new("SHA384Context")
    local digest = ffi.new("uint8_t[?]", 48)
    lib.SHA384_Init(context)
    lib.SHA384_Update(context, str, #str)
    lib.SHA384_Final(digest, context)
    local result = {}
    for i=0,47 do
        result[i+1] = string.char(digest[i])
    end
    return table.concat(result)
end

return sha384
