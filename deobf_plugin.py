import binascii
import hashlib

from idaapi import *
from idautils import *
from idc import *
from collections import deque

from unicorn_emulator.unicorn_emulator import unicorn_emu

def patch_nops(start_ea, end_ea):
    """patches nop instructions (0x90) on all bytes. not including last byte
    (WASN'T USED IN PLUGIN. KEPT FOR REFERENCING)
    """
    for ea in range(start_ea, end_ea):
        patch_byte(ea, 0x90)


def patch_jmp(src_ea, dst_ea):
    """patching src_ea address with a jmp instr into dst_ea
    (WASN'T USED IN PLUGIN. KEPT FOR REFERENCING)
    """
    jmp_inst = b'\xe9'
    jmp_inst += int.to_bytes(dst_ea - (src_ea + 5), 4, byteorder='little')
    
    for i in range(5):
        patch_byte(src_ea + i, jmp_inst[i])


def find_starting_bb(function, flowchart):
    """finds the first basic block of certain function.
    (WASN'T USED IN PLUGIN. KEPT FOR REFERENCING)
    """
    for bb in flowchart:
        if bb.start_ea == function.start_ea:
            return bb
    return None


def bbs_bfs(start_bb):
    """searches for all reachable basic blocks using BFS search 
    (WASN'T USED IN PLUGIN. KEPT FOR REFERENCING)
    """
    q = deque([start_bb])
    found_bbs = []
    while len(q) > 0:
        current_bb = q.popleft()
        #if current_bb.id not in found_bbs:
        if (current_bb.start_ea, current_bb.end_ea) not in [(bb.start_ea, bb.end_ea) for bb in found_bbs]:
            found_bbs.append(current_bb)
            for succ_bb in current_bb.succs():
                q.append(succ_bb)
    return found_bbs


def find_bbs_per_function(ea):
    """retrieves all basic blocks for a function.

    the return format is a list of tuples, where each tuple contains
    (start_ea, last_instruction_in_basic_block_ea)
    """
    function = get_func(ea)
    flowchart = FlowChart(function)

    return [(bb.start_ea, prev_head(bb.end_ea)) for bb in flowchart]
    

def find_potential_junk_codes(ea, exclusion_list):
    """finding potential blocks of code which could be junk code.
    receives exclusion list format (start_ea, end_ea) (exclusive end_ea)

    current heuristic is basic block which contains 5 unpopular assembly instructions.
    could be expanded to any other heuristic.

    return format is a list of the next tuple type: (start_ea, start_ea_of_next_bb, start_ea_of_curr_bb)
    """
    bad_mnem = []
    bad_mnem += ['shr', 'shl', 'aad', 'cbw', 'ror', 'xadd', 'bt', 'btc', 'bswap', 'aaa', 'aas', 'daa', 'clc']
    bad_mnem += ['bsf', 'cdq', 'cmc', 'cwd', 'pushf', 'popf', 'nop', 'stc', 'lahf', 'das', 'bsr']
    reachable = find_bbs_per_function(ea)
    print(f'[+] found reachable {len(reachable)} blocks')

    potent_bbs = []
    OCC_THRESHOLD = 4
    for bb in reachable:
        num_occ = 0
        start_addr = None
        addr = bb[0]
        while addr < bb[1]:
            has_been_removed = False
            for start, end in exclusion_list:
                if start <= addr < end:
                    addr = end
                    has_been_removed = True
                    break
            if has_been_removed:
                continue
            if print_insn_mnem(addr) in bad_mnem:
                num_occ += 1
                if start_addr is None:
                    start_addr = addr
            if num_occ >= OCC_THRESHOLD:
                potent_bbs.append((start_addr, bb[1], bb[0]))
                break
            addr = next_head(addr)
    return potent_bbs


def remove_junk_code(emu, start_ea, end_ea):
    """receives address, and attemps to remove junk code form that address and onwards.
    simulates the instructions on unicorn engine, and stops on first instruction which
    preserves the machine state as is.

    if that happens it calls to add_hidden_range()

    returns the actual range removed or None otherwise.
    """
    print(f'[+] attempting to remove at {hex(start_ea)}:{hex(end_ea)}')

    code = b''
    ea = start_ea
    while ea < end_ea:
        code += get_bytes(ea, get_item_size(ea))
        ea = next_head(ea)

    emu.load_code(code)
    emu.emulate()
    res = emu.find_matching_machine_state()
    if res is not None and res[0] == 0:
        res = None
    if res is not None:
        next_ea = res[0] + start_ea
        ea = prev_head(next_ea)
        
        flags = emu.get_flags_string()
        add_hidden_range(start_ea, next_ea, flags, "", "", 0x0000ff)
        request_refresh(0xffffffff)                    
        print(f'[+] removed {hex(start_ea)}:{hex(next_ea)}')
        return start_ea, next_ea

    print(f'[-] the code is not junk')
    return None


def remove_junk_per_func(emu, ea):
    """main function

    attemps to remove all junk codes of functoin ea belongs to.
    function fails if ea doesn't belongs to a function.

    - look for potential code blocks
    - emulates it in unicorn to check whether it's junk code
    - does the same procedure MAX_TRIES times when going one instruction back (in case heuristics failed)
    - checks whether any more potentials blocks left
    - rinse and repeat untill no blocks left in function.
    """
    if get_func(ea) == None:
        print(f'[-] address given - {hex(ea)} does not belong to a function')
        return False

    MAX_TRIES = 4 # we receiving heuristic starting ea, and trying to go back.
    removal_list = [] # contains all removed code ranges

    print(f'[+] attempting to remove junk code for function {get_func_name(ea)}')
    
    potential_addrs = find_potential_junk_codes(ea, removal_list)
    while len(potential_addrs) > 0:
        print(f'[+] found potential {len(potential_addrs)} blocks')

        counter = 0
        for start_ea, end_ea, bb_start in potential_addrs:
            for _ in range(MAX_TRIES):
                res_range = remove_junk_code(emu, start_ea, end_ea)
                if res_range is not None:
                    removal_list.append(res_range)
                    break
                if start_ea == bb_start:
                    break
                start_ea = prev_head(start_ea)
        potential_addrs = find_potential_junk_codes(ea, removal_list)
    
    print(f'[+] successfully removed {len(removal_list)} blocks')

#------------------------------------------------------------------------------
# IDA Plugin
#------------------------------------------------------------------------------

VERSION = "v1.0"
AUTHORS = ['Alex Ilgayev']

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return deobf_junk_t()

class deobf_junk_t(plugin_t):

    flags = PLUGIN_FIX
    comment = ""
    help = ""
    wanted_name = "Deobfuscate Junk Code"
    wanted_hotkey = "Shift+D"

    def __init__(self):
        self._emu = unicorn_emu()

    def init(self):
        return PLUGIN_OK

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        ea = here()
        remove_junk_per_func(self._emu, ea)

    def term(self):
        pass


    

