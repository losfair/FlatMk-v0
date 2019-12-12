print("{")
for i in range(32, 256):
    print("IDT[{}].set_handler_fn(core::mem::transmute(intr_{} as usize));".format(i, i))
print("}")