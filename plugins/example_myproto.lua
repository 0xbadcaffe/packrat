-- example_myproto.lua
-- Custom protocol dissector for "MyProto" running on TCP port 9999.
--
-- Wire format:
--   [0:2]  magic   uint16  0xDEAD
--   [2:1]  version uint8
--   [3:1]  command uint8   (0=PING, 1=PONG, 2=DATA, 3=FIN)
--   [4:2]  length  uint16  payload byte count
--   [6:]   payload bytes
--
-- Install: copy to ~/.config/packrat/plugins/
-- Reload:  press [r] inside packrat

local myproto = Proto("MyProto", "My Custom Protocol")

local f_magic   = ProtoField.uint16("myproto.magic",   "Magic",   base.HEX)
local f_version = ProtoField.uint8 ("myproto.version", "Version", base.DEC)
local f_command = ProtoField.uint8 ("myproto.command", "Command", base.DEC)
local f_length  = ProtoField.uint16("myproto.length",  "Length",  base.DEC)
local f_payload = ProtoField.bytes ("myproto.payload",  "Payload")

myproto.fields = { f_magic, f_version, f_command, f_length, f_payload }

local COMMANDS = { [0]="PING", [1]="PONG", [2]="DATA", [3]="FIN" }

function myproto.dissector(buf, pinfo, tree)
    local pkt_len = buf:len()
    if pkt_len < 6 then return end

    pinfo.cols.protocol = "MyProto"

    local magic   = buf(0, 2):uint()
    local version = buf(2, 1):uint8()
    local command = buf(3, 1):uint8()
    local length  = buf(4, 2):uint16()

    local subtree = tree:add(myproto, buf(0, pkt_len), "MyProto Header")

    subtree:add(f_magic,   buf(0, 2))
    subtree:add(f_version, buf(2, 1))

    local cmd_label = COMMANDS[command] or string.format("UNKNOWN(%d)", command)
    subtree:add("Command", string.format("%d (%s)", command, cmd_label))

    subtree:add(f_length, buf(4, 2))

    if pkt_len > 6 and length > 0 then
        local payload_len = math.min(length, pkt_len - 6)
        subtree:add(f_payload, buf(6, payload_len))
        -- Show ASCII preview if printable
        local raw = buf(6, payload_len):string()
        subtree:add("Payload (ASCII)", raw)
    end

    if magic ~= 0xDEAD then
        subtree:add("Warning", string.format("Bad magic: expected 0xDEAD, got 0x%04x", magic))
    end
end

DissectorTable.get("tcp.port"):add(9999, myproto)
