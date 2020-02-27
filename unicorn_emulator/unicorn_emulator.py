import binascii
import hashlib  

from unicorn import *
from unicorn.x86_const import *

class unicorn_emu(object):
    ADDRESS    = 0x1000000
    ESP_OFFSET = 0x100000
    EBP_OFFSET = 0x100100
    MEM_SIZE   = 16 * 1024 * 1024 

    # dictionary that maps from instruction code offset to machine state before executing that instruction.
    # will be filled during hooking in emulation.
    _machine_state_arr = []

    def __init__(self):
        self._emu = Uc(UC_ARCH_X86, UC_MODE_32)
        self._emu.mem_map(self.ADDRESS, self.MEM_SIZE)
        self._end_mem_address = self.ADDRESS + self.MEM_SIZE

    def load_code(self, code):
        self._code = code
        self._emu.mem_write(self.ADDRESS, self._code)

    def get_flags_string(self):
        eflags = self._emu.reg_read(UC_X86_REG_EFLAGS)
        zero = (eflags & 0x0040) >> 6
        carry = eflags & 0x1
        overflow = (eflags & 0x0800) >> 11
        ret = f'Z:{zero}:C:{carry}:O:{overflow}'
        return ret

    def _get_all_regs(self):
        r_eax = self._emu.reg_read(UC_X86_REG_EAX)
        r_ebx = self._emu.reg_read(UC_X86_REG_EBX)
        r_ecx = self._emu.reg_read(UC_X86_REG_ECX)
        r_edx = self._emu.reg_read(UC_X86_REG_EDX)
        r_esi = self._emu.reg_read(UC_X86_REG_ESI)
        r_edi = self._emu.reg_read(UC_X86_REG_EDI)
        r_esp = self._emu.reg_read(UC_X86_REG_ESP)
        r_ebp = self._emu.reg_read(UC_X86_REG_EBP)
        return r_eax, r_ebx, r_ecx, r_edx, r_esi, r_edi, r_esp, r_ebp

    def _get_mem_hash(self, start_addr, end_addr):
        """calculate sha1 of the binary memory data to check integrity.
        not including the end_addr
        """
        data = self._emu.mem_read(start_addr, end_addr - start_addr)
        m = hashlib.sha1()
        m.update(data)
        hex_hash = binascii.hexlify(m.digest())
        
        return hex_hash

    def _get_machine_state(self):
        """returns machine state which is tuple of registers and mem hash
        """
        stack_hash = self._get_mem_hash(self._emu.reg_read(UC_X86_REG_ESP), self._end_mem_address)
        regs = self._get_all_regs()
        return regs, stack_hash

    def find_matching_machine_state(self):
        """iterates over list of machine states which was generated during emulation.
        searches for existence of two similar states. (prefer the bigger code offset)

        returns the machine state included code offset if found a match.
        returns None otherwise.
        """

        orig_state_arr = self._machine_state_arr
        while True:
            if len(orig_state_arr) < 1:
                return None
        
            orig_state = orig_state_arr[0][1]
            potential_matching = orig_state_arr[1:][::-1]
            for offset, state in potential_matching:
                if state == orig_state:
                    if offset == 0:
                        continue
                    return offset, state
            orig_state_arr = orig_state_arr[1:]

        return None

    def emulate(self):
        """emulates loaded assembly code using unicorn engine.
        it will hook every instruction, and save machine state for each one.
        that snaphost will be used to check whether there is junk code which can be removed.

        machine state is defined as registers values, and stack data.
        any other data read/write will throw excetion which can be deducted into active instructions.

        return bool if succeeded running or failed.
        """

        def hook_code(uc, address, size, user_data):
            self._machine_state_arr.append((address - self.ADDRESS, self._get_machine_state()))


        self._emu.reg_write(UC_X86_REG_ESP, self.ADDRESS + self.ESP_OFFSET)
        self._emu.reg_write(UC_X86_REG_EBP, self.ADDRESS + self.EBP_OFFSET)

        self._emu.reg_write(UC_X86_REG_EAX, 0x1337)
        self._emu.reg_write(UC_X86_REG_EBX, 0x1336)
        self._emu.reg_write(UC_X86_REG_ECX, 0x1335)
        self._emu.reg_write(UC_X86_REG_EDX, 0x1334)
        self._emu.reg_write(UC_X86_REG_EDI, 0x1333)
        self._emu.reg_write(UC_X86_REG_ESI, 0x1332)
        self._emu.reg_write(UC_X86_REG_EFLAGS, 0x0)

        self._emu.hook_add(UC_HOOK_CODE, hook_code)

        try:
            self._emu.emu_start(self.ADDRESS, self.ADDRESS + len(self._code)) 
            self._machine_state_arr.append((len(self._code), self._get_machine_state()))
        except UcError:
            return False # we have some arbitrary memory read/write.
        return True
