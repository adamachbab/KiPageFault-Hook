# KiPageFault Hook – Windows Kernel C++ POC

This repository contains an educational demonstration of how to locate and intercept the internal Windows kernel routine `KiPageFault`, redirecting execution to a custom handler.  
The goal is to illustrate **low-level operating system internals and reverse engineering concepts**, not for production or malicious use.

---

## What Does This Code Do?

The driver scans the in-memory image of `ntoskrnl.exe` in search of the byte signature that identifies the `KiPageFault` function.  
Once found, it patches the beginning of the routine so that execution jumps to a custom function:

```cpp
void routine() {
    dbg_print("[handler] kipagefault routine initialized\n");
}
```

From that point on, every time a page fault occurs, this handler executes before the original implementation.
`KiPageFault Sig: 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xF9`
