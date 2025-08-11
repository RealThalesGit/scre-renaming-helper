import ida_funcs
import ida_bytes
import binascii
import json

funcs = {}
for i in range(ida_funcs.get_func_qty()):
    f = ida_funcs.getn_func(i)
    if not f:
        continue
    start = f.start_ea
    size = f.end_ea - start
    if size <= 0:
        continue
    bytes_ = ida_bytes.get_bytes(start, size)
    if not bytes_:
        continue
    name = ida_funcs.get_func_name(start)
    funcs[f"0x{start:x}"] = {
        "name": name,
        "bytes": binascii.hexlify(bytes_).decode()
    }

with open("target_functions.json", "w") as f:
    json.dump(funcs, f, indent=2)

print(f"Exported {len(funcs)} functions to target_functions.json")
