import argparse
import base64

from elftools.elf.elffile import ELFFile
from capstone import *
import re

good_list=[".init",".plt",".plt.got",".text",".fini","__libc_thread_freeres_fn","__libc_freeres_fn"]
# A partir de la section "info" d'une relocation, je récupére son nom dans dynstr
def get_str_from_dynstr_from_rel(rel,elf,addrsize):
    if (addrsize == '64'):
        info=rel['r_info']>>32
    else:
        info = rel['r_info'] >> 8
    if(elf.get_section_by_name('.dynstr')==None):
        return None
    else:
        return  elf.get_section_by_name('.dynstr').get_string(elf.get_section_by_name('.dynsym').get_symbol(info).entry['st_name'])
def is_hex_value(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False
def get_string_fromSTR(n, byte_array):
    strings = byte_array.data().split(b'\x00')
    if n < len(strings):
        return strings[n].decode('utf-8')
    else:
        return None
def get_next_key(symbols, current_key):
    greater_keys = [key for key in symbols if key > current_key]
    return min(greater_keys) if greater_keys else None
def get_prev_key(symbols, current_key):
    lower_keys = [key for key in symbols if key < current_key]
    return max(lower_keys) if lower_keys else None
class Dism:
    def __init__(self,elffile):
        self.symbols={}
        self.op_str = {}
        self.mnemonic = {}
        self.bytes = {}
        self.section_entry = {}
        self.hexbytes={}
        # Récupération pour l'affichage si on est en 64 ou 32 bits
        self.addr_size = (elffile.header['e_ident']['EI_CLASS'].split("ELFCLASS")[1])
        if (self.addr_size == '64'):
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            relplt = elffile.get_section_by_name('.rela.plt')
            reldyn = elffile.get_section_by_name('.rela.dyn')

        else:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            relplt = elffile.get_section_by_name('.rel.plt')
            reldyn = elffile.get_section_by_name('.rel.dyn')
        dynSymbols = {}
        if(not relplt==None):
            for rel in relplt.iter_relocations():
                dynSymbols[rel.entry['r_offset']] = get_str_from_dynstr_from_rel(rel, elffile, self.addr_size)
        if (not reldyn == None):
            for rel in reldyn.iter_relocations():
                dynSymbols[rel.entry['r_offset']] = get_str_from_dynstr_from_rel(rel, elffile, self.addr_size)
        if (self.addr_size == '64'):
            base=0
        else:
            base = elffile.get_section_by_name(".got.plt")['sh_addr']
        symbols = {}
        # Boucle qui va rajouter dans symbols, l'adress des dyn stub et leur nom pour bien les afficher dans .plt
        for i in md.disasm(elffile.get_section_by_name('.plt').data(),
                           elffile.get_section_by_name('.plt').header['sh_addr']):
            if (i.mnemonic == "jmp" and len(i.op_str.strip().split()) >> 1):
                matches = re.findall(r'\[(?:[^\]]*?)(0x[0-9a-fA-F]+|\d+)', i.op_str)
                match = re.search(r'[+-]', i.op_str)
                if (self.addr_size == '64'):
                    base=i.address+round(len(i.bytes))
                if (matches[0].startswith('0x')):
                    val = int(matches[0], 16)
                else:
                    val = int(matches[0])
                if (match == None):
                    symbols[i.address] = dynSymbols[val]
                else:
                    if (match[0] == '+'):
                        if (dynSymbols.__contains__(int(base) + val)):
                            symbols[i.address] = dynSymbols[int(base) + val]
                    elif (match[0] == '-'):
                        if (dynSymbols.__contains__(int(base) - val)):
                            symbols[i.address] = dynSymbols[int(base) - val]
            # Boucle qui va rajouter dans symbols, l'adress des dyn stub et leur nom pour bien les afficher dans .plt.got
        if(not elffile.get_section_by_name('.plt.got')==None):
            for i in md.disasm(elffile.get_section_by_name('.plt.got').data(),
                               elffile.get_section_by_name('.plt.got').header['sh_addr']):
                if (i.mnemonic == "jmp" and len(i.op_str.strip().split()) >> 1):
                    matches = re.findall(r'\[(?:[^\]]*?)(0x[0-9a-fA-F]+|\d+)', i.op_str)
                    match = re.search(r'[+-]', i.op_str)
                    if (self.addr_size == '64'):
                        base = i.address + round(len(i.bytes))
                    if (matches[0].startswith('0x')):
                        val = int(matches[0], 16)
                    else:
                        val = int(matches[0])
                    if (match[0] == '+'):
                        if (dynSymbols.__contains__(int(base) + val)):
                            symbols[i.address] = dynSymbols[int(base) + val]
                    elif (match[0] == '-'):
                        if (dynSymbols.__contains__(int(base) - val)):
                            symbols[i.address] = dynSymbols[int(base) - val]
        # Je créer un tableau contenant tout les symboles
        if (not elffile.get_section_by_name('.symtab') == None):
            for sym in elffile.get_section_by_name('.symtab').iter_symbols():
                symbols[sym.entry['st_value']] = elffile.get_section_by_name('.strtab').get_string(
                    sym.entry['st_name'])
        self.symbols = symbols
        for section in elffile.iter_sections():
            if section.header["sh_type"] == "SHT_PROGBITS" and good_list.__contains__(elffile.get_section_by_name('.shstrtab').get_string(section.header['sh_name'])):
                on=1
                for i in md.disasm(section.data(), section.header['sh_addr']):
                    if (on==1):
                        self.section_entry[i.address]=elffile.get_section_by_name('.shstrtab').get_string(section.header['sh_name'])
                        on=0
                    hex_bytes = ' '.join(f'{b:02x}' for b in i.bytes)
                    self.hexbytes[i.address] = hex_bytes
                    self.bytes[i.address] = i.bytes
                    self.mnemonic[i.address] = i.mnemonic
                    self.op_str[i.address] = i.op_str
        for entry in self.section_entry:
            if(not symbols.__contains__(entry)):
                symbols[entry]=symbols[get_next_key(symbols,entry)]+"-"+hex(get_next_key(symbols,entry)-entry)
    def show_code(self):
        for adress in self.mnemonic.__iter__():
            if(self.section_entry.__contains__(adress)):
                print(f"\n\nDisassembly of section {self.section_entry[adress]}")
            if (self.symbols.__contains__(adress)):
                print(f"\n  {adress:#0{round(int(self.addr_size)/4)}x}   <{self.symbols[adress]}>\n")
            if (self.mnemonic[adress] == "call" and is_hex_value(self.op_str[adress])):

                if (self.symbols.__contains__(int(self.op_str[adress], 16))):
                    print(
                        f"\t{hex(adress)}: {self.hexbytes[adress]:<{20}}\t{self.mnemonic[adress]} {self.op_str[adress]} <{self.symbols[int(self.op_str[adress], 16)]}>")
                else:
                    print(f"\t{hex(adress)}: {self.hexbytes[adress]:<{20}}\t{self.mnemonic[adress]} {self.op_str[adress]}")
            else:
                print(f"\t{hex(adress)}: {self.hexbytes[adress]:<{20}}\t{self.mnemonic[adress]} {self.op_str[adress]}")
