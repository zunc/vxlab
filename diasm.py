__author__ = 'khoai'

import pefile
import distorm3
from distorm3 import Decode, Decode16Bits, Decode32Bits, Decode64Bits

class bDiasm:
    def __init__(self, file_name):
        print "__init_ : bDiasm"
        self.file_name = file_name
        self.total_instructions = 0

    def diasm(self):
        self.total_instructions = 0

        #
        pe = pefile.PE(self.file_name)
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_ava = ep + pe.OPTIONAL_HEADER.ImageBase
        self.ep_ava = ep_ava

        print "--- pe section"
        code_section = None
        for section in pe.sections:
            print "\t", section.Name.replace("\0", " "), hex(section.VirtualAddress), hex(section.Misc_VirtualSize), hex(section.SizeOfRawData)
            if (ep >= section.VirtualAddress) & (ep <= (section.VirtualAddress + section.SizeOfRawData)):
                code_section = section

        print "--- entry point"
        print "\tep:", hex(ep)
        print "\tcode section:", code_section.Name.replace("\0", " ")
        print "\tcode size:", hex(code_section.SizeOfRawData)
        print ""

        va_fisrt = code_section.VirtualAddress
        va_last = code_section.VirtualAddress + code_section.SizeOfRawData
        all_code = pe.get_memory_mapped_image()[va_fisrt:va_last]
        image_base = pe.OPTIONAL_HEADER.ImageBase

        asm_code = dict()
        for op in distorm3.Decompose(pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress, all_code, Decode32Bits):
            # print("\t0x%x\t%s\t%d" % (op.address, op.mnemonic, op.size))
            asm_code[op.address] = op
            # if op.flowControl == 'FC_CND_BRANCH':
            #     print 'FC_CND_BRANCH: 0x%x' % (op.operands[0].value)
            self.total_instructions += 1

        return asm_code


# BLOCK_OPEN_SUB  = "SUB_OPEN"
# BLOCK_CLOSE_SUB = "SUB_CLOSE"
BLOCK_OPEN_LOC  = "LOC_OPEN"
BLOCK_CLOSE_LOC = "LOC_CLOSE"
BLOCK_INS       = "NONE"
BLOCK_OPEN_APP  = "APP_OPEN"

class InsNode(object):
    def __init__(self, ins, block_type):
        self.ins = ins
        self.block_type = block_type
        self.note = ''

    def __getitem__(self):
        return (self.ins, self.block_type)

    def __setitem__(self, ins, block_type):
        self.ins = ins
        self.block_type = block_type

    def __getattr__(self, name):
        try:
            return getattr(self.np_array, name)
        except AttributeError:
            raise AttributeError(
                 "'InsNode' object has no attribute {}".format(name))

class GraphNode(object):
    def __init__(self, name):
        self.name = name
        self.traveled = False
        self.test = 0
        self.children = dict()
        self.data = []
        self.userData = None # for custom data

    def addChild(self, child):
        if child.name not in self.children.keys():
            self.children[child.name] = child

    def countChild(self):
        return len(self.children)

class ControlFlowGenerator:
    def __init__(self, asm_code):
        print "__init_ : ControlFlowGenerator"
        self.asm_code = asm_code
        self.first_pos = asm_code.keys()[1]
        self.last_pos = asm_code.keys()[-1]
        self.total_instructions = len(asm_code)
        self.control_flow = dict()

    def findNearPosition(self, pos):
        nearPos = pos
        while (nearPos >= self.first_pos) & (nearPos <= self.last_pos):
            if self.asm_code.has_key(nearPos) == True:
                return nearPos
            nearPos += 1
        return -1

    def getBranchOffset(self, ins):
        pos_next = ins.operands[0].value;
        # if ins.operands[0].type == "":
        #     print ins.operands[0].type == ""
        # elif ins.operands[0].type == "Register":
        #     print ins.operands[0].type == "Register"
        if ins.operands[0].type == "Immediate":
            pos_next = self.findNearPosition(pos_next)
            if pos_next < 0:
                print "wtf: pos_next < 0, ins.operands[0].value: %x" % (ins.operands[0].value)
                quit()
            else:
                self.buildControlFlow(pos_next)

    def addBlockSignByIns(self, ins, block_type):
        offset = ins.operands[0].value;
        if ins.operands[0].type == "Immediate":
            if offset in self.asm_code.keys():
                self.block_signs[offset].block_type = block_type
            else:
                pos = self.findNearPosition(offset)
                if pos > 0:
                    self.block_signs[pos].block_type = block_type
                    self.block_signs[pos].note = "redirect: 0x%x" % (offset)
                # else:
                #     print "not found address: offset: 0x%x , op: 0x%x" % (ins.address, offset)

    def addBlockSignByOffset(self, offset, block_type):
        if offset in self.asm_code.keys():
            self.block_signs[offset].block_type = block_type
        else:
            pos = self.findNearPosition(offset)
            if pos > 0:
                self.block_signs[pos].block_type = block_type
                self.block_signs[pos].note = "redirect: 0x%x" % (offset)
            # else:
            #     print "not found address: op: 0x%x" % (offset)

    def buildOpenBlockSign(self, ep):
        self.block_signs = dict()

        # --- convert to dict InsNode
        for pos in self.asm_code:
            ins = self.asm_code[pos]
            self.block_signs[ins.address] = InsNode(ins, BLOCK_INS)

        # --- build block signs
        self.block_signs[ep].block_type = BLOCK_OPEN_LOC
        for pos in self.asm_code:
            ins = self.asm_code[pos]
            if ins.flowControl == 'FC_CALL':
                #print "FC_CALL"
                self.addBlockSignByIns(ins, BLOCK_OPEN_LOC)
                # ---
            if ins.flowControl == 'FC_UNC_BRANCH':
                # print "FC_UNC_BRANCH"
                self.addBlockSignByIns(ins, BLOCK_OPEN_LOC)
            elif ins.flowControl == 'FC_CND_BRANCH':
                f_branch = ins.address + ins.size
                self.addBlockSignByOffset(f_branch, BLOCK_OPEN_LOC)
                self.addBlockSignByIns(ins, BLOCK_OPEN_LOC)
            if ins.flowControl == 'FC_RET':
                # print "FC_RET"
                self.addBlockSignByOffset(ins.address, BLOCK_CLOSE_LOC)
            # else:
            #     # some trick
            #     if len(ins.operands) == 2:
            #         if (ins.operands[0].name == 'EDI') & (ins.operands[0].name == ins.operands[1].name):
            #             self.addBlockSignByOffset(ins.address, BLOCK_OPEN_LOC)

    def buildTextBlock(self, offset):
        self.buildOpenBlockSign(offset)
        self.buildGraphBlock()
        scode = ""
        for offset in sorted(self.block_code):
            node = self.block_code[offset]
            scode += "loc_%x:\n" % (offset)
            for ins in node:
                scode += ("\t0x%x\t%s\n" % (ins.address, str(ins)))
                # with hex opcode
                #scode += ("\t0x%x\t%-32s%s\n" % (ins.address, ins.instructionBytes.encode("hex"),str(ins)))
        return scode

    def convertDict2array(self):
        self.codes = []
        for offset in sorted(self.block_signs):
            self.codes.append(self.block_signs[offset])

    def buildGraphBlock(self):
        self.block_code = dict()
        # |           |--- code ---|
        # |           |xor edi, 1  |
        # |[offset]-> |mov edx, 2  |
        # |           |------------|
        # |

        # wait_close = False
        lsCode = []
        open_block_add = 0
        for offset in self.block_signs:
            if open_block_add == 0:
                open_block_add = offset

            # if wait_close == True:
            #     lsCode = []
            node = self.block_signs[offset]
            if node.block_type == BLOCK_OPEN_LOC:
                self.block_code[open_block_add] = lsCode
                lsCode = [node.ins]
                open_block_add = node.ins.address
                #lsCode.append(node.ins)
            elif node.block_type == BLOCK_CLOSE_LOC:
                lsCode.append(node.ins)
                self.block_code[open_block_add] = lsCode
                lsCode = []
                open_block_add = self.findNearPosition(node.ins.address + 1)
            else:
                lsCode.append(node.ins)

    def addNodeByIns(self, node, ins):
        offset = ins.operands[0].value;
        if ins.operands[0].type == "Immediate":
            if offset in self.asm_code.keys():
                newNode = self.traceCode(offset)
                if newNode != None:
                    node.addChild(newNode)
            else:
                pos = self.findNearPosition(offset)
                if pos > 0:
                    newNode = self.traceCode(pos)
                    if newNode != None:
                        node.addChild(newNode)
                        # self.block_signs[pos].note = "redirect: 0x%x" % (offset)
                else:
                    print "not found address: offset: 0x%x , op: 0x%x" % (ins.address, offset)

    def addNodeByOffset(self, node, offset):
        if offset in self.asm_code.keys():
            newNode = self.traceCode(offset)
            if newNode != None:
                node.addChild(newNode)
        else:
            pos = self.findNearPosition(offset)
            if pos > 0:
                newNode = self.traceCode(pos)
                if newNode != None:
                    node.addChild(newNode)
                    # self.block_signs[pos].note = "redirect: 0x%x" % (offset)
            else:
                print "not found address, op: 0x%x" % (offset)

    nodeGraph = dict()
    def traceCode(self, offset):
        # branch edge in control flow
        #print "> 0x%x" % (offset)
        pos = offset
        if pos not in self.block_code.keys():
            return None
        if pos in self.nodeGraph.keys():
            return self.nodeGraph[pos]

        lsIns = self.block_code[pos]
        node = GraphNode(offset)
        for ins in lsIns:
            node.data.append(ins)
            #if ins.flowControl == 'FC_CALL':
            #    self.addNodeByIns(node, ins)
            if ins.flowControl == 'FC_UNC_BRANCH':
                 self.addNodeByIns(node, ins)
            elif ins.flowControl == 'FC_CND_BRANCH':
                 f_branch = ins.address + ins.size
                 self.addNodeByOffset(node, f_branch)
                 self.addNodeByIns(node, ins)
            elif ins.flowControl == 'FC_RET':
                self.nodeGraph[node.name] = node
                return node
        self.nodeGraph[node.name] = node
        return node

    def topbotCode(self):
        # top to bot edge in control flow
        #print "> 0x%x" % (offset)
        for offset in self.nodeGraph:
            node = self.nodeGraph[offset]
            lastIns = node.data[-1]
            lastFlow = lastIns.flowControl
            if (lastFlow != 'FC_RET') & (lastFlow != 'FC_UNC_BRANCH') & (lastFlow != 'FC_UNC_BRANCH'):
                lastInsAdd = lastIns.address
                nextInsAdd = self.findNearPosition(lastInsAdd + 1)
                if nextInsAdd in self.nodeGraph.keys():
                    node.addChild(self.nodeGraph[nextInsAdd])

    def buildControlFlow(self, offset):
        print "1. buildOpenBlockSign"
        self.buildOpenBlockSign(offset)
        self.convertDict2array()
        print "2. buildGraphBlock"
        self.buildGraphBlock()
        print "3. traceCode"
        node_root = self.traceCode(offset)
        self.topbotCode()
        return node_root

    def test(self):
        print "hi"

def genControlFlowGraph(filePath, offset = 0)

    file = bDiasm(filePath)
    asm_code = file.diasm()

    cfg_generator = ControlFlowGenerator(asm_code)

    # offset = file.ep_ava
    cfgNode = cfg_generator.buildControlFlow(0x4013a0) #(file.ep_ava)


#--- get text
# 4013a0
# scode = control_flow_generator.buildTextBlock(diasm.ep_ava)
# print scode

#print "node: %d" % (cfg.countChild())

# control_flow = control_flow_generator.buildControlFlow(diasm.ep_ava)

# for block_pos in control_flow:
#     block = control_flow[block_pos]
#     print "loc_%x:" % (block_pos)
#     for ins in block:
#         print("\t0x%x\t%s" % (ins.address, str(ins)))