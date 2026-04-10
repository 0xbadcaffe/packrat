-- example_modbus.lua
-- Modbus TCP dissector (port 502).
--
-- Modbus TCP ADU layout:
--   [0:2]  Transaction Identifier  uint16
--   [2:2]  Protocol Identifier     uint16  (always 0x0000)
--   [4:2]  Length                  uint16  (bytes following, including Unit ID)
--   [6:1]  Unit Identifier         uint8
--   [7:1]  Function Code           uint8
--   [8:]   Data                    bytes
--
-- Supported function codes: 1-6, 15, 16, 43

local modbus = Proto("Modbus", "Modbus TCP")

local f_tid    = ProtoField.uint16("modbus.tid",  "Transaction ID", base.HEX)
local f_pid    = ProtoField.uint16("modbus.pid",  "Protocol ID",    base.HEX)
local f_len    = ProtoField.uint16("modbus.len",  "Length",         base.DEC)
local f_uid    = ProtoField.uint8 ("modbus.uid",  "Unit ID",        base.DEC)
local f_fc     = ProtoField.uint8 ("modbus.fc",   "Function Code",  base.DEC)
local f_data   = ProtoField.bytes ("modbus.data", "Data")

modbus.fields = { f_tid, f_pid, f_len, f_uid, f_fc, f_data }

local FC_NAMES = {
    [1]  = "Read Coils",
    [2]  = "Read Discrete Inputs",
    [3]  = "Read Holding Registers",
    [4]  = "Read Input Registers",
    [5]  = "Write Single Coil",
    [6]  = "Write Single Register",
    [15] = "Write Multiple Coils",
    [16] = "Write Multiple Registers",
    [43] = "Read Device Identification",
    -- error codes (FC | 0x80)
    [129] = "Error: Read Coils",
    [130] = "Error: Read Discrete Inputs",
    [131] = "Error: Read Holding Registers",
    [132] = "Error: Read Input Registers",
    [133] = "Error: Write Single Coil",
    [134] = "Error: Write Single Register",
}

local EXCEPTION_CODES = {
    [1] = "Illegal Function",
    [2] = "Illegal Data Address",
    [3] = "Illegal Data Value",
    [4] = "Server Failure",
    [5] = "Acknowledge",
    [6] = "Server Busy",
}

function modbus.dissector(buf, pinfo, tree)
    local pkt_len = buf:len()
    if pkt_len < 8 then return end

    pinfo.cols.protocol = "Modbus/TCP"

    local tid = buf(0, 2):uint16()
    local pid = buf(2, 2):uint16()
    local len = buf(4, 2):uint16()
    local uid = buf(6, 1):uint8()
    local fc  = buf(7, 1):uint8()

    local fc_name = FC_NAMES[fc] or string.format("FC %d", fc)
    local is_error = fc >= 128

    local subtree = tree:add(modbus, buf(0, pkt_len), "Modbus/TCP")
    subtree:add(f_tid, buf(0, 2))
    subtree:add(f_pid, buf(2, 2))
    subtree:add(f_len, buf(4, 2))
    subtree:add(f_uid, buf(6, 1))
    subtree:add("Function Code", string.format("%d (%s)%s", fc, fc_name, is_error and " [EXCEPTION]" or ""))

    if pkt_len > 8 then
        local data_len = pkt_len - 8
        if is_error and data_len >= 1 then
            local exc = buf(8, 1):uint8()
            local exc_name = EXCEPTION_CODES[exc] or string.format("Unknown(%d)", exc)
            subtree:add("Exception Code", string.format("%d (%s)", exc, exc_name))
        elseif fc == 3 or fc == 4 then
            -- Read Holding/Input Registers response
            if data_len >= 1 then
                local byte_count = buf(8, 1):uint8()
                subtree:add("Byte Count", tostring(byte_count))
                local reg_count = math.floor(byte_count / 2)
                for i = 0, reg_count - 1 do
                    local off = 9 + i * 2
                    if off + 2 <= pkt_len then
                        local val = buf(off, 2):uint16()
                        subtree:add(string.format("Register[%d]", i),
                            string.format("%d (0x%04x)", val, val))
                    end
                end
            end
        elseif fc == 1 or fc == 2 then
            -- Read Coils/Discrete Inputs: starting addr + quantity (request)
            if data_len >= 4 then
                local addr = buf(8, 2):uint16()
                local qty  = buf(10, 2):uint16()
                subtree:add("Starting Address", string.format("%d (0x%04x)", addr, addr))
                subtree:add("Quantity",         tostring(qty))
            end
        else
            subtree:add(f_data, buf(8, data_len))
        end
    end
end

DissectorTable.get("tcp.port"):add(502, modbus)
