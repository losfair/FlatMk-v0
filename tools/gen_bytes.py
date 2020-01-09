import sys

with open(sys.argv[1], "rb") as f:
    data = f.read()
    bstr = []
    for b in data:
        bstr.append(hex(b))
    print("const uint8_t {}[{}] = {};\n".format(sys.argv[2], len(bstr), "{" + ",".join(bstr) + "}"))
