local bit = require("bit")
local string = require("string")

local K = {
    [0]=0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
}

local function sha384(str)
    local function rightrotate(value, shift)
        return bit.bor(bit.rshift(value, shift), bit.lshift(value, 64 - shift))
    end

    local function uint64_to_str(w, n)
        local s = ""
        for i = 1, n do
            s = s .. string.char(bit.band(bit.rshift(w, (n - i) * 8), 0xff))
        end
        return s
    end

    local function str_to_uint64(str)
        local w = 0
        for i = 1, string.len(str) do
            w = bit.bor(bit.lshift(w, 8), string.byte(str, i))
        end
        return w
    end

    local function fill_block(block, i, w)
        for j = 0, 15 do
            w[j] = str_to_uint64(string.sub(block, i + j * 8, i + j * 8 + 7))
        end
        for j = 16, 79 do
            local s0 = rightrotate(w[j - 15], 1) ~ rightrotate(w[j - 15], 8) ~ bit.rshift(w[j - 15], 7)
            local s1 = rightrotate(w[j - 2], 19) ~ rightrotate(w[j - 2], 61) ~ bit.rshift(w[j - 2], 6)
            w[j] = w[j - 16] + s0 + w[j - 7] + s1
        end
    end

    local function sha384_transform(state, block)
        local w = {}
        fill_block(block, 1, w)

        local a, b, c, d, e, f, g, h = state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]

        for i = 0, 79 do
            local s0 = rightrotate(a, 28) ~ rightrotate(a, 34) ~ rightrotate(a, 39)
            local maj = (a & b) ~ (a & c) ~ (b & c)
            local t2 = s0 + maj
            local s1 = rightrotate(e, 14) ~ rightrotate(e, 18) ~ rightrotate(e, 41)
            local ch = (e & f) ~ (~e & g)
            local t1 = h + s1 + ch + K[i] + w[i]
            h, g, f, e, d, c, b, a = g, f, e, bit.band(d + t1, 0xffffffffffffffff), c, b, a, bit.band(t1 + t2, 0xffffffffffffffff)
        end

        state[0], state[1], state[2], state[3] = bit.band(state[0] + a, 0xffffffffffffffff), bit.band(state[1] + b, 0xffffffffffffffff), bit.band(state[2] + c, 0xffffffffffffffff), bit.band(state[3] + d, 0xffffffffffffffff)
        state[4], state[5], state[6], state[7] = bit.band(state[4] + e, 0xffffffffffffffff), bit.band(state[5] + f, 0xffffffffffffffff), bit.band(state[6] + g, 0xffffffffffffffff), bit.band(state[7] + h, 0xffffffffffffffff)
    end

    local block_size = 128
    local message_length = string.len(str)
    local bit_length = message_length * 8
    local padding_length = block_size - ((bit_length + 129) % block_size + 1)
    local padded_message = str .. string.char(128) .. string.rep(string.char(0), padding_length / 8) .. uint64_to_str(bit_length, 8)

    local state = {
        [0]=0xcbbb9d5d, 0x629a292a, 0x9159015a, 0x152fecd8,
        0x67332667, 0xffc00b31, 0x8eb44a87, 0xdb0c2e0d
    }

    for i = 1, string.len(padded_message), block_size do
        sha384_transform(state, string.sub(padded_message, i, i + block_size - 1))
    end

    return uint64_to_str(state[0], 8) .. uint64_to_str(state[1], 8) .. uint64_to_str(state[2], 8) .. uint64_to_str(state[3], 8) .. uint64_to_str(state[4], 8) .. uint64_to_str(state[5], 8)
end

return sha384
