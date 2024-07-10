import idaapi
import idc
import ida_range
import ida_funcs
import ida_nalt
import ida_segment
import ida_segregs
import idautils
import ida_auto
import ida_bytes
import ida_name

import capstone
from struct import pack, unpack

# search all ida python api here: https://hex-rays.com/products/ida/support/idapython_docs/

class ProgramFirmware:
    def __init__(self, segments: dict[int, bytes], entrys: list[int], thumb: bool, ivs: int):
        self.segments = segments
        self.entrys = entrys
        self.thumb = thumb
        self.ivs = ivs
    
    def __str__(self):
        return f"""ProgramFirmware {{
    segments: [ {', '.join([f'[{hex(s)}, {hex(s + len(v))})'for s, v in self.segments.items()])} ],
    entrys: [{', '.join(map(hex, self.entrys))}],
    type: ProgramType.FIRMWARE,
    thumb: {self.thumb},
    interrupt vector length: {self.ivs}
}}"""

def detect_thumb(addrs: list[int]):
    cnt = 0
    for addr in addrs:
        cnt += (addr & 1)
    return (cnt / len(addrs) > 0.8)

def parse_firmware(file: str) -> ProgramFirmware | None:

    with open(file, "rb") as f:
        buf = f.read()

    print(f"[*] Try to search interrupt vectors in file...", end='\r')

    interrupt_vectors_size = 0x80

    # flash is always mapped into a contiguous memory space
    size = len(buf)
    size_bit = len(bin(size)) - 2

    # if size_bit > 16:
    #     print("[-] firmware too large (>= 2^16), base finding result might be incorrect.")

    # print(hex(size))

    bases = dict()
    not_null_addr = 0

    for i in range(0, interrupt_vectors_size, 4):
        v = unpack("<I", buf[i:i+4])[0]
        # ignore null addr
        if v == 0:
            continue
        not_null_addr += 1
        off = v & ((1 << size_bit)-1)
        # print(hex(v), hex(off), end = " ")
        if off >= size:
            continue
        # use higher bits as base
        base = ((v >> size_bit) << size_bit)
        # print(base)
        if base in bases:
            bases[base] += 1
        else:
            bases[base] = 1

    bases = sorted(bases.items(), key = lambda x:-x[1])
    total_cnt = sum(map(lambda x:x[1], bases))

    if total_cnt < not_null_addr * 0.9 or bases[0][1] < total_cnt * 0.9:
        print(f"[-] Try to search interrupt vectors in file: cannot find enough valid pointers")
        return None

    base_addr = bases[0][0]
    print(f"[+] format: ARM32 firmware with interrupt vectors")
    print(f"[!] firmware base addr: {hex(base_addr)}")
    # search for more interrupt vectors as entrypoint
    bad_keys = 0
    entrys = set()
    for cur in range(0, min(0x800, size), 4):
        v = unpack("<I", buf[cur:cur+4])[0]
        if v == 0:
            continue

        off = v - base_addr
        if off >= size:
            bad_keys += 1
            if bad_keys == 2:
                cur -= 8
                break
            continue
        bad_keys = 0
        entrys.add(v)

    print("[+] interrupt vectors:", list(map(hex, entrys)))

    return ProgramFirmware(
        segments = {bases[0][0]: buf},
        entrys = list(entrys),
        thumb = detect_thumb(list(entrys)),
        ivs = cur + 4
    )

AGGRESSIVE = False

filename = ida_nalt.get_input_file_path()
print(f"[*] input file: {filename}")

prog = parse_firmware(filename)

if prog is None:
    exit(-1)

print(prog)

entrys = prog.entrys

# rebase program
base_addr = min(prog.segments.keys())
print(f"[*] Rebase program to {hex(base_addr)}")

ida_segment.rebase_program(base_addr - ida_segment.get_first_seg().start_ea, 0)

# set thumb code mode
# https://reverseengineering.stackexchange.com/questions/12698/ida-pro-how-to-select-arm-or-thumb-mode-when-using-make-code-command
# https://reverseengineering.stackexchange.com/questions/21990/how-to-set-virtual-t-register-programmatically-in-ida-python

if prog.thumb:
    ida_segregs.split_sreg_range(base_addr, idaapi.str2reg("T"), 1, idaapi.SR_user)


# create functions

print(f"[*] Creating functions...")
for func in entrys:
    ida_funcs.add_func(func & (-1 ^ 1))
    ida_auto.auto_wait()

# create interrupt vectors table

ida_bytes.create_dword(base_addr, prog.ivs, False)
ida_name.set_name(base_addr, "interrupt_vectors", 0)


print(f"[*] linear scaning...")

INST_STEP = 2 if prog.thumb else 4
mode = capstone.CS_MODE_THUMB if prog.thumb else capstone.CS_MODE_ARM
md = capstone.Cs(capstone.CS_ARCH_ARM, mode)


for start_addr in idautils.Segments():
    end_addr = idc.get_segm_end(start_addr)
    addr = start_addr
    while addr < end_addr:
        func = ida_funcs.get_func(addr)
        flags = ida_bytes.get_flags(addr)

        # ignore data
        if flags != ida_bytes.FF_UNK and flags & ida_bytes.FF_CODE != ida_bytes.FF_CODE:
            addr += INST_STEP
            continue
        
        if func is None:
            print(f"[*] try analyze as function at {hex(addr)}...")
            data = ida_bytes.get_bytes(addr, 4, 0)
            inst = next(md.disasm_lite(data, addr, 1), None)
            if not AGGRESSIVE and (inst is None or not inst[2].startswith('push') or inst[3].find('lr') == -1):
                addr += INST_STEP
                continue
            success = ida_funcs.add_func(addr)
            ida_auto.auto_wait()
            if not success:
                print(f"[-] reverting at {hex(addr)}...")
                ida_bytes.del_items(addr)
                addr += INST_STEP
                continue
            print(f"[+] linear analyze found new function at {hex(addr)}.")
        
        rs = ida_range.rangeset_t()
        ida_funcs.get_func_ranges(rs, func)
        # print(funcea)
        for r in rs:
            if addr >= r.start_ea and addr < r.end_ea:
                addr = r.end_ea
                break
        else:
            addr += INST_STEP

print("[*] Done.")

