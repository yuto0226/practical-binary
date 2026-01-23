import sys
import struct
from elftools.elf.enums import ENUM_EI_OSABI, ENUM_E_MACHINE, ENUM_SH_TYPE_BASE
from elftools.elf.elffile import ELFFile


def patch(fname="lvl3"):
    with open(fname, "rb") as file:
        print(f"[*] reading {fname}")
        elf = ELFFile(file)
        file.seek(0)
        buf = bytearray(file.read())

        # OSABI
        print(
            f"[*] patch OSABI(off 0x07): 0x{buf[0x07]:02X} -> ELFOSABI_NONE(0x{ENUM_EI_OSABI['ELFOSABI_SYSV']:02X})")
        struct.pack_into('<B', buf, 0x7, ENUM_EI_OSABI['ELFOSABI_SYSV'])

        # recover e_machine
        print(
            f"[*] patch e_machine(off 0x12): 0x{buf[0x12]:04X} -> EM_X86_64(0x{ENUM_E_MACHINE['EM_X86_64']:04X})")
        struct.pack_into('<H', buf, 0x12, ENUM_E_MACHINE['EM_X86_64'])

        # recover e_phoff
        print(f"[*] patch e_phoff(0x20): 0x{buf[0x20]:016X} -> 0x40")
        struct.pack_into('<Q', buf, 0x20, 0x40)

        shoff = elf.header['e_shoff']           # 0x1180
        shentsize = elf.header['e_shentsize']   # 0x40
        text_idx = elf.get_section_index(".text")

        text_sh = shoff + text_idx * shentsize

        print(f"[*] .text section header offset: 0x{text_sh:02X}")

        # sh_type
        print(
            f"[*] patch .text sh_type(0x{text_sh + 4:X}): 0x{buf[text_sh + 4]:X} -> SHT_PROGBITS(0x{ENUM_SH_TYPE_BASE['SHT_PROGBITS']:X})")
        buf[text_sh + 4] = ENUM_SH_TYPE_BASE['SHT_PROGBITS']

    with open(f"{fname}.patch", "wb") as file:
        print(f"[*] writing {fname}.patch")
        file.write(buf)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        patch(sys.argv[1])
    else:
        patch()

    print("[+] done")
