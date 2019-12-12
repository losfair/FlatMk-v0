for i in range(32, 256):
    print("interrupt!(intr_{}, __intr_{}, frame, registers, {{ handle_external_interrupt(frame, registers, {}) }});".format(i, i, i))
