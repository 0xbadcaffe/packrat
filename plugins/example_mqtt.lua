-- example_mqtt.lua
-- MQTT 3.1.1 dissector (TCP port 1883 plaintext, 8883 TLS).
--
-- MQTT Fixed Header:
--   Byte 0:  [7:4] Packet Type, [3:0] Flags
--   Byte 1+: Remaining Length (variable-length encoding, 1-4 bytes)
--
-- Packet types: CONNECT(1), CONNACK(2), PUBLISH(3), PUBACK(4),
--   SUBSCRIBE(8), SUBACK(9), UNSUBSCRIBE(10), UNSUBACK(11),
--   PINGREQ(12), PINGRESP(13), DISCONNECT(14)

local mqtt = Proto("MQTT", "MQTT 3.1.1")

local f_type    = ProtoField.uint8 ("mqtt.type",    "Packet Type",     base.DEC)
local f_flags   = ProtoField.uint8 ("mqtt.flags",   "Flags",           base.HEX)
local f_remlen  = ProtoField.uint8 ("mqtt.remlen",  "Remaining Len",   base.DEC)
local f_topic   = ProtoField.string("mqtt.topic",   "Topic")
local f_payload = ProtoField.bytes ("mqtt.payload", "Payload")
local f_msgid   = ProtoField.uint16("mqtt.msgid",   "Message ID",      base.DEC)

mqtt.fields = { f_type, f_flags, f_remlen, f_topic, f_payload, f_msgid }

local PTYPE = {
    [1]  = "CONNECT",    [2]  = "CONNACK",   [3]  = "PUBLISH",
    [4]  = "PUBACK",     [5]  = "PUBREC",    [6]  = "PUBREL",
    [7]  = "PUBCOMP",    [8]  = "SUBSCRIBE", [9]  = "SUBACK",
    [10] = "UNSUBSCRIBE",[11] = "UNSUBACK",  [12] = "PINGREQ",
    [13] = "PINGRESP",   [14] = "DISCONNECT",
}

local CONNACK_RC = {
    [0] = "Accepted",
    [1] = "Refused: bad protocol version",
    [2] = "Refused: identifier rejected",
    [3] = "Refused: server unavailable",
    [4] = "Refused: bad credentials",
    [5] = "Refused: not authorized",
}

-- Decode MQTT variable-length integer; returns (value, bytes_consumed)
local function decode_varlen(buf, offset)
    local mul = 1
    local val = 0
    local n   = 0
    repeat
        if offset + n >= buf:len() then return 0, 1 end
        local b = buf(offset + n, 1):uint8()
        val = val + (b & 0x7F) * mul
        mul = mul * 128
        n = n + 1
        if (b & 0x80) == 0 then break end
    until n >= 4
    return val, n
end

-- Read a 2-byte length-prefixed UTF-8 string from buf at offset
local function read_mqtt_string(buf, offset)
    if offset + 2 > buf:len() then return "", 2 end
    local slen = buf(offset, 2):uint16()
    if offset + 2 + slen > buf:len() then return "", 2 + slen end
    return buf(offset + 2, slen):string(), 2 + slen
end

function mqtt.dissector(buf, pinfo, tree)
    local pkt_len = buf:len()
    if pkt_len < 2 then return end

    pinfo.cols.protocol = "MQTT"

    local byte0   = buf(0, 1):uint8()
    local ptype   = byte0 >> 4
    local flags   = byte0 & 0x0F
    local pname   = PTYPE[ptype] or string.format("UNKNOWN(%d)", ptype)

    local remlen, vlen = decode_varlen(buf, 1)
    local header_end   = 1 + vlen -- offset after fixed header

    local title = string.format("MQTT %s (type=%d, flags=0x%x, remlen=%d)",
        pname, ptype, flags, remlen)
    local subtree = tree:add(mqtt, buf(0, pkt_len), title)

    subtree:add(f_type,   buf(0, 1))
    subtree:add("Packet Type", string.format("%d (%s)", ptype, pname))
    subtree:add(f_flags,  buf(0, 1))
    subtree:add(f_remlen, buf(1, vlen))

    -- Per-type variable header + payload
    local off = header_end

    if ptype == 1 then
        -- CONNECT
        local proto_name, n1 = read_mqtt_string(buf, off); off = off + n1
        local proto_level = buf(off, 1):uint8(); off = off + 1
        local conn_flags  = buf(off, 1):uint8(); off = off + 1
        local keepalive   = buf(off, 2):uint16(); off = off + 2
        local client_id, n2 = read_mqtt_string(buf, off); off = off + n2

        subtree:add("Protocol Name",  proto_name)
        subtree:add("Protocol Level", tostring(proto_level))
        subtree:add("Connect Flags",  string.format("0x%02x", conn_flags))
        subtree:add("Keep Alive",     string.format("%d s", keepalive))
        subtree:add("Client ID",      client_id)

    elseif ptype == 2 then
        -- CONNACK
        local sp = buf(off, 1):uint8() & 0x01; off = off + 1
        local rc = buf(off, 1):uint8()
        subtree:add("Session Present", tostring(sp == 1))
        subtree:add("Return Code",
            string.format("%d (%s)", rc, CONNACK_RC[rc] or "Unknown"))

    elseif ptype == 3 then
        -- PUBLISH
        local qos = (flags >> 1) & 0x03
        local dup = (flags >> 3) & 0x01
        local ret = flags & 0x01
        subtree:add("QoS",    tostring(qos))
        subtree:add("DUP",    tostring(dup == 1))
        subtree:add("Retain", tostring(ret == 1))

        local topic, n3 = read_mqtt_string(buf, off); off = off + n3
        subtree:add("Topic", topic)

        if qos > 0 and off + 2 <= pkt_len then
            local msg_id = buf(off, 2):uint16(); off = off + 2
            subtree:add(f_msgid, buf(off - 2, 2))
        end
        local pay_len = pkt_len - off
        if pay_len > 0 then
            local pay_str = buf(off, pay_len):string()
            subtree:add("Payload", pay_str)
        end

    elseif ptype == 8 then
        -- SUBSCRIBE
        local msg_id = buf(off, 2):uint16(); off = off + 2
        subtree:add(f_msgid, buf(off - 2, 2))
        while off + 3 <= pkt_len do
            local topic, tn = read_mqtt_string(buf, off); off = off + tn
            local qos = buf(off, 1):uint8(); off = off + 1
            subtree:add("Subscribe", string.format("'%s' QoS=%d", topic, qos))
        end

    elseif ptype == 12 then
        subtree:add("Note", "PING request — keepalive check")
    elseif ptype == 13 then
        subtree:add("Note", "PING response")
    elseif ptype == 14 then
        subtree:add("Note", "Client disconnecting")
    end
end

DissectorTable.get("tcp.port"):add(1883, mqtt)
DissectorTable.get("tcp.port"):add(8883, mqtt)  -- MQTT over TLS
