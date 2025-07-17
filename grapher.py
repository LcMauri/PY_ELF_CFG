import disas

conditional=["ja","jae","jb","jbe","loope","LOOPNE","LOOPNZ","LOOPZ","LOOP","jc","jcxz","je","jg","jge","jl","jle","jna","jnae","jnb","jnbe","jnc","jne","jng","jnge","jnl","jnle","jno","jnp","jns","jnz","jo","jp","jpe","jpo","js","jz","JA","JAE","JB","JBE","JC","JCXZ","JE","JG","JGE","JL","JLE","JNA","JNAE","JNB","JNBE","JNC","JNE","JNG","JNGE","JNL","JNLE","JNO","JNP","JNS","JNZ","JO","JP","JPE","JPO","JS","JZ"]
end_list=["retn","ret","hlt"]
class Graph:
    def __init__(self,dism,elffile):
        start=0
        end = 0
        self.tab = []
        temp=[]
        for adress in sorted(dism.bytes):
            if(dism.symbols.__contains__(adress)):
                temp.append(adress)
        for i in range(len(temp)):
            if(i==len(temp)-1):
                self.tab.append(Tab(dism,elffile,temp[i],max(dism.bytes.keys()),dism.symbols[temp[i]]))
            else:
                self.tab.append(Tab(dism,elffile,temp[i],disas.get_prev_key(dism.bytes,temp[i+1]),dism.symbols[temp[i]]))
class Tab:
    def __init__(self,dism,elffile,start,end,name=None):
        self.cells= {}
        self.start = start
        self.end = end
        self.name=name
        tmp_addr = start
        addr_list = []
        tmp_link = []
        tmp_cells={}
        counteur=0
        while tmp_addr != end:
            addr_list.append(tmp_addr)
            tmp_addr = tmp_addr + round(len(dism.bytes[tmp_addr]))
        addr_list.append(end)
        deb=addr_list[0]
        fin=0
        for i in range(len(addr_list)):
            fin = addr_list[i]
            if(conditional.__contains__(dism.mnemonic[addr_list[i]])):

                if(i==len(addr_list)-1):
                    tmp_cells[counteur] = (deb, fin, int(dism.op_str[addr_list[i]], 16), 0)
                else:
                    tmp_cells[counteur] = (deb, fin, int(dism.op_str[addr_list[i]], 16), addr_list[i + 1])
                    deb = addr_list[i+1]
                counteur=counteur+1
                #print(f"{self.name} {tmp_cells} ")
            elif (end_list.__contains__(dism.mnemonic[addr_list[i]])):
                tmp_cells[counteur] = (deb, fin,0,0)
                counteur=counteur+1
                if(len(addr_list)-1==i):
                    bahrien=0
                else:
                    deb = addr_list[i + 1]


            elif (dism.mnemonic[addr_list[i]]=="jmp" and disas.is_hex_value(dism.op_str[addr_list[i]])):
                if (not i == len(addr_list) - 1):
                    tmp_cells[counteur] = (deb, fin, int(dism.op_str[addr_list[i]], 16), 0)
                    deb = addr_list[i + 1]
                else:
                    tmp_cells[counteur] = (deb, fin, 0 ,0)

                counteur = counteur + 1
            elif (i == len(addr_list) - 1):
                tmp_cells[counteur] = (deb, fin,0,0)
                counteur=counteur+1
        if(len(tmp_cells)>0):
            if(len(tmp_cells)>300):
                print(f"TOO BIG {self.name}  {len(tmp_cells)}")
            else:
                for i in range(len(tmp_cells)):
                    for y in range(len(tmp_cells)):

                        if(tmp_cells[y][0] < tmp_cells[i][2] < tmp_cells[y][1]):
                            deb=disas.get_prev_key(dism.mnemonic,tmp_cells[i][2])
                            tmp_cells[counteur] = (tmp_cells[i][2], tmp_cells[y][1], tmp_cells[y][2], tmp_cells[y][3])
                            tmp_cells[y] = (tmp_cells[y][0],deb , 0, tmp_cells[i][2])
                            counteur=counteur+1
        for i in range(len(tmp_cells)):
            self.cells[tmp_cells[i][0]]=Cells(tmp_cells[i])
class Cells:
    def __init__(self,cell):
        self.link=(cell[2],cell[3])
        self.code=(cell[0],cell[1])
        self.done=False