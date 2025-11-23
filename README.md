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

```cpp
nt_status_t startup( ) {
    std::uintptr_t nt_base = module::ntos_base( ); dbg_print( "[kipagefault] ntoskrnl base = %p\n", nt_base );
    if ( !nt_base ) { dbg_print( "[kipagefault] ntoskrnl base NULL\n" ); return nt_status_t::unsuccessful; }

    std::uint8_t* ki_page_fault = nullptr;

    std::uint8_t sig[ ] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xF9 };
    for ( int i = 0; i < 0x800000; i++ ) {
        if ( rtl_compare_memory( ( std::uint8_t* )nt_base + i, sig, sizeof( sig ) ) == sizeof( sig ) ) {
            ki_page_fault = ( std::uint8_t* )nt_base + i;
            dbg_print( "[kipagefault] signature found in offset 0x%X\n", i ); break;
        }
    }

    if ( !ki_page_fault ) { dbg_print( "[kipagefault] could not find KiPageFault signature\n"  ); return nt_status_t::unsuccessful; }
    dbg_print( "[kipagefault] KiPageFault address: %p\n", ki_page_fault );

    std::uint8_t patch[ 13 ];

    // mov r11
    patch[ 0 ] = 0x49;
    patch[ 1 ] = 0xBB;
    *( std::uint64_t* )&patch[ 2 ] = ( std::uint64_t )routine;

    // jmp r11
    patch[ 10 ] = 0x41;
    patch[ 11 ] = 0xFF;
    patch[ 12 ] = 0xE3;

    std::uint8_t irql = ke_raise_irql_to_dpc_level( );
    std::uintptr_t cr0 = __readcr0( );
    __writecr0( cr0 & ~0x10000 );
    rtl_copy_memory( ki_page_fault, patch, sizeof( patch ) );
    __writecr0( cr0 );
    ke_lower_irql( irql );

    return nt_status_t::success;
}
```

---

## Disclaimer

This project is for educational and research purposes only.
I do not condone or support malicious use of this information.
Use responsibly, in controlled environments, and at your own risk.

---
