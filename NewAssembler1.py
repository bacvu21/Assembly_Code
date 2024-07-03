
'''

Assembler for the 'RTM-16' Computer

Takes in an assembly code file (eg: Prog.asm) and produces the machine
code (eg: Prog.mc) to load into the 'RTM-16' computer's memory.

Usage: python3 <Path>Assembler.py <Path>Prog.asm <Path>Prog.mc

'''

import sys
import os
import re
import math

NUM_PROG_ARGS = 3

# Positions for code parts
POS_OPCODE = 10
POS_AM     = 8
POS_REG_A  = 4
POS_REG_B  = 0

# Regular expressions for the various argument combinations
RE_REGS = r'(R[0-5]|FP|IND|SP|FL|TMP|CNT|IAR|IR|ACC|MAR)'
RE_NUM = r'#[F]?-?0?[BX]?[0-9A-F.]+'
RE_ADDR = r'0?[BX]?[0-9A-F]+'

RE_REG_ONLY         = r'^' + RE_REGS + r'$'                         #  Rx
RE_NUM_ONLY         = r'^' + RE_NUM + r'$'                          #  #n
RE_ADDR_ONLY        = r'^' + RE_ADDR + r'$'                         #  addr
RE_REG_REG          = r'^' + RE_REGS + r',' + RE_REGS + r'$'        #  Rx,Ry
RE_REG_ADDR         = r'^' + RE_REGS + r',' + RE_ADDR + r'$'        #  Rx,addr
RE_NUM_REG          = r'^' + RE_NUM + r',' + RE_REGS + r'$'         #  #n,Rx
RE_NUM_ADDR         = r'^' + RE_NUM + r',' + RE_ADDR + r'$'         #  #n,addr 
RE_ADDR_REG         = r'^' + RE_ADDR + r',' + RE_REGS + r'$'        #  addr,Rx
RE_ADDR_ADDR        = r'^' + RE_ADDR + r',' + RE_ADDR + r'$'        #  addr,addr
RE_NUM_REG_REG      = r'^' + RE_NUM + r',' + RE_REGS + r',' + RE_REGS + r'$'   #  #n,Rx,Ry
RE_ADDR_REG_REG     = r'^' + RE_ADDR + r',' + RE_REGS + r',' + RE_REGS + r'$'  #  addr,Rx,Ry
RE_REG_IND          = r'^\[' + RE_REGS + r'\]$'                     #  [Rx]
RE_ADDR_IND         = r'^\(' + RE_ADDR + r'\)$'                     #  (addr)
RE_REG_REG_IND      = r'^' + RE_REGS + r',\(' + RE_REGS + r'\)$'    #  Rx,(Ry)
RE_REG_ADDR_IND     = r'^' + RE_REGS + r',\[' + RE_ADDR + r'\]$'    #  Rx,[addr]
RE_NUM_REG_IND      = r'^' + RE_NUM + r',\(' + RE_REGS + r'\)$'     #  #n,(Rx)
RE_ADDR_REG_IND     = r'^\[' + RE_ADDR + r'\],' + RE_REGS + r'$'    #  [addr],Rx
RE_REG_IDX          = r'^' + RE_REGS + r'\+IND$'                    #  Rx+IND
RE_REG_IDX_REG      = r'^' + RE_REGS + r'\+IND,' + RE_REGS + r'$'   #  Rx+IND,Ry
RE_REG_REG_IDX      = r'^' + RE_REGS + r',' + RE_REGS + r'\+IND$'   #  Rx,Ry+IND
RE_REG_ADDR_REG_IDX = r'^' + RE_REGS + r',' + RE_ADDR + r'\+' + RE_REGS + r'$'  #  Rx,addr+Ry
RE_ADDR_REG_REG_IDX = r'^' + RE_ADDR + r'\+' + RE_REGS + r',' + RE_REGS + r'$'  #  addr+Rx,Ry
RE_REG_POST         = r'^\[' + RE_REGS + r'\]\+$'                   #  [Rx]+
RE_REG_POST_REG     = r'^\[' + RE_REGS + r'\]\+,' + RE_REGS + r'$'  #  [Rx]+,Ry

# Instructions Table
# Each instruction stores the tuple: (opcode, args list)
# args list - A list of regular expressions that detail the valid argument formats
#             for the instruction - These also correspond to the 'Addres Mode' bits
INSTR_OPCODE = 0
INSTR_FORMATS = 1

instrs = {'DATA'   : (0b000000, [RE_ADDR_REG, RE_NUM_REG, RE_NUM_ADDR, RE_ADDR_ADDR]),
          'CMPA'   : (0b000000, [None, None, None, RE_NUM_ADDR]),
          'LOAD'   : (0b000001, [RE_ADDR_REG, RE_REG_IDX_REG, RE_ADDR_REG_IND, RE_REG_REG]),
          'STORE'  : (0b000010, [RE_REG_ADDR, RE_REG_REG_IDX, RE_REG_ADDR_IND, RE_REG_REG]),
          'JMP'    : (0b000011, [RE_ADDR_ONLY, RE_ADDR_IND, RE_REG_IND, RE_REG_ONLY]),
          'JSR'    : (0b000100, [RE_ADDR_ONLY, RE_REG_IDX, None, RE_REG_ONLY]),
          'PUSH'   : (0b000101, [RE_NUM_ONLY, RE_REG_ONLY, RE_ADDR_IND, RE_ADDR_ONLY]),
          'POP'    : (0b000110, [RE_ADDR_ONLY, RE_REG_ONLY, RE_REG_IND]),
          'MOVE'   : (0b000111, [RE_ADDR_ADDR, RE_REG_REG]),
          'EXGR'   : (0b001000, [RE_REG_REG]),
          'SUBA'   : (0b001000, [None, RE_NUM_ADDR]),
          'ADD'    : (0b001001, [RE_NUM_REG_REG, RE_REG_REG, RE_ADDR_REG_REG, RE_REG_POST_REG]),
          'SHR'    : (0b001010, [RE_NUM_REG_REG, RE_REG_REG, RE_NUM_REG_IND]),
          'SHL'    : (0b001011, [RE_NUM_REG_REG, RE_REG_REG, RE_NUM_REG_IND]),
          'NOT'    : (0b001100, [RE_ADDR_ONLY, RE_REG_REG, RE_REG_REG_IND]),
          'AND'    : (0b001101, [RE_NUM_REG_REG, RE_REG_REG, RE_ADDR_REG_REG, RE_REG_POST_REG]),
          'OR'     : (0b001110, [RE_NUM_REG_REG, RE_REG_REG, RE_ADDR_REG_REG, RE_REG_POST_REG]),
          'XOR'    : (0b001111, [RE_NUM_REG_REG, RE_REG_REG, RE_ADDR_REG_REG, RE_REG_POST_REG]),
          'CMP'    : (0b010000, [RE_NUM_REG, RE_REG_REG, RE_ADDR_REG, RE_ADDR_ADDR]),
          'INC'    : (0b010001, [RE_REG_ONLY, None, RE_ADDR_ONLY]),
          'DEC'    : (0b010010, [RE_REG_ONLY, None, RE_ADDR_ONLY]),
          'JUMPIF' : (0b010011, [RE_ADDR_ONLY, RE_REG_ONLY]),
          'EXGM'   : (0b010100, [RE_ADDR_ADDR]),
          'CLF'    : (0b010101, []),
          'END'    : (0b010110, []),
          'SUB'    : (0b010111, [RE_NUM_REG_REG, RE_REG_REG, RE_ADDR_REG_REG, RE_ADDR_ADDR]),
          'MULT'   : (0b011000, [RE_NUM_REG_REG, RE_REG_REG, RE_ADDR_REG_REG, RE_REG_POST_REG]),
          'DIV'    : (0b011001, [RE_NUM_REG_REG, RE_REG_REG]),
          'RET'    : (0b011010, []),
          'CLR'    : (0b011011, [RE_REG_ONLY]),
          'SPLASH' : (0b011100, [RE_ADDR_ONLY]),
          'PIXEL'  : (0b011100, [None, RE_ADDR_REG_REG]),
          'STOREA' : (0b011101, [RE_REG_ADDR_REG_IDX]),
          'LOADA'  : (0b011110, [RE_ADDR_REG_REG_IDX])}

NO_ARGS_INSTRS = ['CLF', 'RET', 'END']

# Registers Table
regs = {'R0'  : 0b0000,
        'R1'  : 0b0001,
        'R2'  : 0b0010,
        'R3'  : 0b0011,
        'R4'  : 0b0100,
        'R5'  : 0b0101,
        'FP'  : 0b0110,
        'IND' : 0b0111,
        'SP'  : 0b1000,
        'FL'  : 0b1001,
        'TMP' : 0b1010,
        'CNT' : 0b1011,
        'IAR' : 0b1100,
        'IR'  : 0b1101,
        'ACC' : 0b1110,
        'MAR' : 0b1111} 

RD_ONLY_REGS = ['FL', 'TMP', 'CNT', 'MAR']

# Coditional Jump Commands
condJumps = {'JC'   : 0b0001,
             'JAGT' : 0b0010,
             'JCA'  : 0b0011,
             'JE'   : 0b0100,
             'JCE'  : 0b0101,
             'JAGE' : 0b0110,
             'JALE' : 0b0111,
             'JZ'   : 0b1000,
             'JMIN' : 0b1001,
             'JEZ'  : 0b1010,
             'JNE'  : 0b1011,
             'JPOS' : 0b1100,
             'JNC'  : 0b1101,
             'JNZ'  : 0b1110,
             'JALT' : 0b1111}

# Labels Table
# Each label stores the tuple: (value, directive ?)
# directive ? - True if the label's either EQU, DC or DS, otherwise false
labels = {}
DC_GEN_CODES = 3

# Undefined Labels List 
# A list of labels referenced in instruction arguments that are currently undefined
undef_labels = []

# Floating Point NaN & Inf's
FP_NAN     = 0x7e00
FP_POS_INF = 0x7c00
FP_NEG_INF = 0xfc00


# Helper Functions

# Check that a file's OK
def ProcessFile(file, type):
    # Create the output directory if it doesn't exist
    if type == 'mc':
        dirOut = os.path.dirname(file)
        if dirOut != '' and not os.path.exists(dirOut):
            os.mkdir(dirOut)

    # Check its type
    file_ext = os.path.splitext(file)[1][1:]
    if file_ext != type:
        if type == 'asm':
            print("\nInvalid filename - You should use an 'asm' file as the input file\n")
        elif type == 'mc':
            print("\nInvalid filename - You should use an 'mc' file as the output file\n")
        exit()

    return file

# Delete an invalid machine code file
def DeleteFile(file):
    if os.path.exists(file):
        os.remove(file)

# Write a word to the machine code file
def WriteWord(word):
    global mc, wordcount
    wordcount += 1

    if (wordcount % 16) == 0:
        sep = '\n'
    elif (wordcount % 8) == 0:
        sep = '  '
    else:
        sep = ' '
    while len(word) < 4:
        word = '0' + word

    mc.write(word + sep)

# Remove all spaces from a string
def RemoveSpaces(str_in):
    str_out = ''
    for i in range(len(str_in)):
        if str_in[i] != ' ':
            str_out += str_in[i]
    return str_out

# Get the integer value of a string
def GetNum(str):
    err_msg = 'Invalid number format'
    try:
        if '.' in str:
            # It's a floating point number
            if str.upper().startswith('F'):
                val = dec_to_hex88(str[1:])
            else:
                val = dec_to_hexFPU(str)
            return val

        if str.upper().startswith('0B'):
            val = int(str[2:], base=2)
            if val < 0:
                raise Exception
        elif str.upper().startswith('0X'):
            val = int(str[2:], base=16)
            if val < 0:
                raise Exception
        else:
            val = int(str)
            # Negative number adjustment
            if -(2**15) <= val < 0:
                val += 2**16

        # Are we in the valid 16 bit number range ?
        if val < 0x0000 or val > 0xffff:
            err_msg = 'Value outwith the 16 bit number range'
            raise Exception

        return val
    
    except:
        raise SyntaxError(err_msg)

# Check whether or not a label is valid
def ValidLabel(lbl):
    if lbl in instrs or lbl in regs or lbl in condJumps:
        raise SyntaxError(f"'{lbl}' is an invalid label (It's a reserved word)")

    if lbl in labels:
        return False

    elif lbl[0].isdigit():
        return False

    for c in lbl:
        if not c.isdigit() and not c.isalpha() and c != '_':
            return False

    return True

# Get the number of bytes for an instruction
def InstrLen(instr):
    if instr in NO_ARGS_INSTRS:
        return 1

    # Get the instruction arguments
    nBytes = 1
    instr = instr.split(' ', 1)
    if len(instr) < 2:
        raise SyntaxError(f"'{instr[0]}' is missing its arguments")

    args = RemoveSpaces(instr[1])
    args = args.split(',')
    for arg in args:
        # Check if an argument's: #n, addr, [addr], or (addr)
        arg = arg.strip()
        resNum = re.match(r'^' + RE_NUM + r'$', arg)
        resAddr = re.match(r'^[\[\(]?' + RE_ADDR + r'[\]\)]?$', arg)

        # Check if an argument's: lbl, [lbl] or (lbl)
        if (resNum is None) and (resAddr is None):
            resLbl = re.match(r'^[\[\(]?[A-Z0-9_]+[\]\)]?$', arg)
            lblOK = False
            if resLbl is not None:
                if arg.startswith('[') or arg.startswith('('):
                    arg = arg[1:-1]
                # Registers will be found in the 'match' above - Ignore these
                if arg not in regs:
                    lblOK = True
                    if arg not in labels:
                        # Label yet to be defined
                        undef_labels.append(arg)

        if (resNum is not None) or (resAddr is not None) or lblOK:
            # The argument's one of the above - increment the instruction length
            nBytes += 1

    return nBytes

# Process a directive
def ProcessDirective(name, line):
    global addr

    # Remove any comments 
    if name == 'DC' and '"' in line:
        if ';' in line and (line.find(';') < line.find('"')):
            # The quote's part of the comment
            line = line.split(';')
            line = line[0].strip()
        else:
            # Allow ';'s within DC strings
            parts = line.split('"')
            line = '"'.join(parts[:2]) + '"'
            line = line.strip()
    else:
        line = line.split(';')
        line = line[0].strip()

    # Get the label & its value
    line = line.split(':', 1)
    line = line[1].strip()

    if name == 'DC' and ('"' in line or '(' in line):
        # Don't want to be splitting DC strings or arrays on spaces
        line = line.split(' ', 1)
    else:
        # Get rid of all spaces from the line
        parts = line.split(' ')
        line = []
        for part in parts:
            if part != '':
                line.append(part)

    if len(line) != 2:
        raise NameError(f'Invalid Label at line {lineNo}: {line[0]}')

    lbl = line[0].strip().upper()  # DC's aren't capitalised when read from the assembly file
    val = line[1].strip()

    array = False
    if name == 'DC' and val.startswith('"'):
        # Get a DC string
        if not val.endswith('"'):
            raise NameError(f'Invalid Label at line {lineNo}: {lbl}')
        val = val[1:-1]
    elif name == 'DC' and val.startswith("("):
        # Get a DC array
        if not val.endswith(')'):
            raise NameError(f'Invalid Label at line {lineNo}: {lbl}')
        array = True
        val = val[1:-1]
    elif name != 'EQU':
        # Get an integer value
        if val.startswith('#'):
            val = val[1:]

        val = GetNum(val.strip())

    # Add to label table if valid
    if ValidLabel(lbl):
        # For 'DC' & 'DS' update the storage address
        if name == 'DC':
            labels[lbl] = (str(addr), True)  # (value, directive ?)
            addr = WriteDCCode(val, addr, array)
        elif name == 'DS':
            labels[lbl] = (str(addr), True)
            addr += val
        elif name == 'EQU':
            labels[lbl] = (val, True)
    else:
        if lbl in labels:
            raise NameError(f'Duplicate Label at line {lineNo}: {lbl}')
        else:
            raise NameError(f'Invalid Label at line {lineNo}: {lbl}')

# Write the DC generation code to the machine code file.
# It uses the command: DATA #val,addr
def WriteDCCode(val, addr, array):
    global numDCs

    if isinstance(val, int):
        # Integer generation
        WriteWord('0200')
        WriteWord(hex(val)[2:])
        WriteWord(hex(addr)[2:])
        numDCs += 1
        addr += 1
    elif array:
        # Array generation
        val = val.replace(':',',')
        vals = val.split(',')
        for i in range(len(vals)):
            val = GetNum(vals[i].strip())
            WriteWord('0200')
            WriteWord(hex(val)[2:])
            WriteWord(hex(addr)[2:])
            numDCs += 1
            addr += 1
    else:
        # String generation
        for i in range(len(val)):
            WriteWord('0200')
            WriteWord(hex(ord(val[i]))[2:])
            WriteWord(hex(addr)[2:])
            numDCs += 1
            addr += 1

        # Add a NULL terminator
        WriteWord('0200')
        WriteWord('0000')
        WriteWord(hex(addr)[2:])
        numDCs += 1
        addr += 1
            
    return addr

# Get the register number for an instruction code
def GetRegNum(reg, chk_read_only=False):
    if chk_read_only and reg in RD_ONLY_REGS:
        raise SyntaxError(f"Register '{reg}' is read-only")
    return regs[reg]

# Go through the arguments list for an instruction, and if it's a valid
# format return the instruction bytes, otherwise generate a syntax error.
# The returned tuple is (Instr Byte 1, Instr Byte 2, Instr Byte 3).
def GetInstrBytes(instr, args=None, fmt_list=None):
    res = None

    # Deal with the the instructionss that have no arguments
    if instr in NO_ARGS_INSTRS:
        opcode = instrs[instr][INSTR_OPCODE]
        byte1 = opcode << POS_OPCODE
        return (byte1, None, None)

    # Deal with the the instructionss that have arguments
    for addr_mode, fmt in enumerate(fmt_list):
        if fmt is None:
            continue

        res = re.match(fmt, args)
        if res is not None:
            # Found the matching format
            break

    # No match found
    if res is None:
        if instr in ['LOAD', 'STORE', 'CMP', 'SUB']:
            # These instructions also have a further argument format under
            # 'instrA' - So try this if the other formats haven't matched
            instr += 'A'
            fmt_list = instrs[instr][INSTR_FORMATS]
            return GetInstrBytes(instr, args, fmt_list)
        else:
            raise SyntaxError('Invalid argument list')
    
    # Initialise instruction data
    reg_a = reg_b = 0
    byte2 = byte3 = None
    if instr in condJumps:
        # For conditional jumps: RA = 'Jump Code'
        opcode = instrs['JUMPIF'][INSTR_OPCODE]
        reg_a = condJumps[instr]
    else:
        opcode = instrs[instr][INSTR_OPCODE]

    # To allow 'DATA lbl,Rx' & 'DATA lbl,addr' instructions
    if instr == 'DATA':
        if addr_mode == 0b00:
            addr_mode = 0b01
        elif addr_mode == 0b11:
            addr_mode = 0b10

    # To allow 'PUSH #n' & 'PUSH addr' instructions
    if instr == 'PUSH' and addr_mode == 0b11:
        addr_mode = 0b00

    # Get a list of the arguments
    args = args.split(',')

    if fmt == RE_REG_ONLY:
        # Rx
        reg_b = GetRegNum(args[0], True)
    elif fmt == RE_NUM_ONLY:
        # #n
        byte2 = GetNum(args[0][1:])
    elif fmt == RE_ADDR_ONLY:
        # addr
        byte2 = GetNum(args[0])
    elif fmt == RE_REG_REG:
        # Rx,Ry
        reg_a = GetRegNum(args[0])
        reg_b = GetRegNum(args[1], True)
    elif fmt == RE_REG_ADDR:
        # Rx,addr
        reg_a = GetRegNum(args[0])
        byte2 = GetNum(args[1])
    elif fmt == RE_NUM_REG:
        # #n,Rx
        reg_b = GetRegNum(args[1], True)
        byte2 = GetNum(args[0][1:])
    elif fmt == RE_NUM_ADDR:
        # #n,addr
        byte2 = GetNum(args[0][1:])
        byte3 = GetNum(args[1])
    elif fmt == RE_ADDR_REG:
        # addr,Rx
        reg_b = GetRegNum(args[1], True)
        byte2 = GetNum(args[0])
    elif fmt == RE_ADDR_ADDR:
        # addr,addr
        byte2 = GetNum(args[0])
        byte3 = GetNum(args[1])
    elif fmt == RE_NUM_REG_REG:
        # #n,Rx,Ry
        reg_a = GetRegNum(args[1])
        reg_b = GetRegNum(args[2], True)
        byte2 = GetNum(args[0][1:])
    elif fmt == RE_ADDR_REG_REG:
        # addr,Rx,Ry
        reg_a = GetRegNum(args[1])
        reg_b = GetRegNum(args[2], True)
        byte2 = GetNum(args[0])
    elif fmt == RE_REG_IND:
        # [Rx]
        reg_b = GetRegNum(args[0][1:-1])
    elif fmt == RE_ADDR_IND:
        # (addr)
        byte2 = GetNum(args[0][1:-1])
    elif fmt == RE_REG_REG_IND:
        # Rx,(Ry)
        reg_a = GetRegNum(args[0])
        reg_b = GetRegNum(args[1][1:-1])        
    elif fmt == RE_REG_ADDR_IND:
        # Rx,[addr]
        reg_a = GetRegNum(args[0])
        byte2 = GetNum(args[1][1:-1])
    elif fmt == RE_NUM_REG_IND:
        # #n,(Rx)
        reg_b = GetRegNum(args[1][1:-1])
        byte2 = GetNum(args[0][1:])
    elif fmt == RE_ADDR_REG_IND:
        # [addr],Rx
        reg_b = GetRegNum(args[1], True)
        byte2 = GetNum(args[0][1:-1])
    elif fmt == RE_REG_IDX:
        # Rx+IND
        reg_b = GetRegNum(args[0][:-4])
    elif fmt == RE_REG_IDX_REG:
        # Rx+IND,Ry
        reg_a = GetRegNum(args[0][:-4])
        reg_b = GetRegNum(args[1], True)
    elif fmt == RE_REG_REG_IDX:
        # Rx,Ry+IND
        reg_a = GetRegNum(args[0])
        reg_b = GetRegNum(args[1][:-4])
    elif fmt == RE_REG_ADDR_REG_IDX:
        # Rx,n+Ry
        args_1 = args[1].split('+')
        reg_a = GetRegNum(args[0])
        reg_b = GetRegNum(args_1[1])
        byte2 = GetNum(args_1[0])
    elif fmt == RE_ADDR_REG_REG_IDX:
        # n+Rx,Ry
        args_0 = args[0].split('+')
        reg_a = GetRegNum(args_0[1])
        reg_b = GetRegNum(args[1], True)
        byte2 = GetNum(args_0[0])        
    elif fmt == RE_REG_POST:
        # [Rx]+
        if instr in ['PUSH', 'POP'] or instr in condJumps:
            reg_b = GetRegNum(args[0][1:-2])
        else:
            reg_a = GetRegNum(args[0][1:-2])
    elif fmt == RE_REG_POST_REG:
        # [Rx]+,Ry
        reg_a = GetRegNum(args[0][1:-2])
        reg_b = GetRegNum(args[1], True)
    else:
        assert False, f'Invalid argument combination ({fmt})'

    # Form the instruction's 1st byte
    byte1 = (opcode << POS_OPCODE) + (addr_mode << POS_AM) + \
            (reg_a << POS_REG_A) + (reg_b << POS_REG_B)

    return (byte1, byte2, byte3)

# Convert a decimal string to a hex floating point number
def dec_to_hexFPU(str):
    # Get the decimal value
    val = float(str)

    # Get the sign bit
    if val < 0:
        val = abs(val)
        sign = '1'
    else:
        sign = '0'
    
    # Get the exponent
    exp = 15
    
    # If the number's 2 or above keep dividing by 2 until it's not.
    # While doing this the exponent must be incremented for each division,
    # so that val * (2**exp) remains equal to the initial number.
    while val >= 2:
        val /= 2
        exp += 1

    # Numbers beyond the normal range are infinite
    if exp > 30:
        if sign == '0':
            return FP_POS_INF
        else:
            return FP_NEG_INF

    # If the number's below 1 keep multiplying by 2 until it's not.
    # While doing this the exponent must be decremented for each multiplication,
    # so that val * (2**exp) remains equal to the initial number.
    while val < 1:
        val *= 2
        exp -= 1
        if exp == 0:
            # It's a subnormal number - exponent can't be lowered further
            val /= 2
            break

    # Get the mantissa
    mant = ''
    
    # Get rid of the leading '1' for normal numbers
    if exp != 0:
        val -= 1
        
    for _ in range(21):
        val = 2 * val
        if val >= 1:
            val -= 1
            mant += '1'
        else:
            mant += '0'

    # Perform rounding if necessary
    if (mant[9] == '0' and mant[10] == '1' and '1' in mant[11:]) or \
        (mant[9] == '1' and mant[10] == '1'):
        mant = mant[:10]
        mantInt = int(mant, 2) + 1
        if hex(mantInt) == '0x400':
            mant = '0' * 10
            exp += 1
        else:
            mant = f'{mantInt:010b}'
    else:
        mant = mant[:10]

    bin_str = sign + f'{exp:05b}' + mant
    return int(bin_str, 2)

# Convert a decimal string to a an '8.8' hex floating point number
def dec_to_hex88(str):
    # Get the decimal value
    val = float(str)

    # Get the 'integer' & 'decimal' parts
    i_part = math.floor(val)
    d_part = val - i_part
    
    if i_part < 0:
        i_part += 2**8

    # Form the '8.8' hex number
    i_part = i_part << 8
    d_part = int(d_part * 256)
    
    hex_88 = i_part + d_part

    return hex_88


# The Main Program

# Check we have the necessary files
num_args = len(sys.argv)
if num_args != NUM_PROG_ARGS:
    print("Invalid input - There must be an 'asm' input file & an 'mc' output file")
    exit()

# Get the 'asm' file to be assembled
fileIn = ProcessFile(sys.argv[1], 'asm')

# Set the 'mc' output file to be generated
fileOut = ProcessFile(sys.argv[-1], 'mc')

try:
    # 1st pass through the assembly code - Add all labels to the labels table
    lineNo = 0
    addr = -1
    gotOrigin = False
    gotStartAddr = False
    wordcount = 0
    numDCs = 0

    with open(fileIn,'r') as asm:
        with open(fileOut,'w') as mc:
            mc.write('v3.0 hex words plain\n')

            for line in asm:
                lineNo += 1
                line = line.strip()

                if not line.startswith('DC'):
                    # Don't capitalise DC's as they may define strings
                    line = line.upper()

                # Set the 'ORIGIN' address
                if line.startswith('ORIGIN'):
                    # Remove any comments 
                    line = line.split(';')
                    line = line[0].strip()

                    line = line.split(' ')
                    addr = GetNum(line[-1].strip()) - 1
                    gotOrigin = True
                    continue

                # Set the 'STARTADDRESS'
                elif line.startswith('STARTADDRESS'):
                    assert gotOrigin, "No 'ORIGIN' defined"
                    # Remove any comments 
                    line = line.split(';')
                    line = line[0].strip()

                    line = line.split(' ')
                    addr = GetNum(line[-1].strip())
                    gotStartAddr = True
                    continue

                # Deal with'EQU' directives
                elif line.startswith('EQU'):
                    ProcessDirective('EQU', line)
                    continue

                # Deal with'DC' directives
                elif line.startswith('DC'):
                    assert gotStartAddr, "No 'STARTADDRESS' defined"                
                    ProcessDirective('DC', line)
                    continue

                # Deal with'DS' directives
                elif line.startswith('DS'):
                    assert gotStartAddr, "No 'STARTADDRESS' defined"
                    ProcessDirective('DS', line)
                    continue

                # Ignore comment lines
                elif line.startswith(';'):
                    continue

                # Ignore blank lines
                if len(line) > 0:
                    assert gotOrigin, "No 'ORIGIN' defined"
                    addr += 1

                    # Remove comments
                    line = line.split(';')
                    line = line[0].strip()

                    # Labels are defined as 'LABEL:'
                    if ':' in line:
                        if line.endswith(':'):
                            lbl = line[:-1]
                            cmd = 'none'
                        else:
                            line = line.split(':')
                            lbl = line[0]
                            cmd = line[1].strip()

                        # Add to label table if valid
                        if ValidLabel(lbl):
                            labels[lbl] = (str(addr), False)  # (value, directive ?)                            print('YYY')
                            if cmd == 'none':
                                addr -= 1
                                continue
                        else:
                            if lbl in labels:
                                raise NameError(f'Duplicate Label at line {lineNo}: {lbl}')
                            else:
                                raise NameError(f'Invalid Label at line {lineNo}: {lbl}')

                        # Adjust next address for double & triple word instructions
                        addr += (InstrLen(cmd) - 1)
                    else:
                        # Adjust next address for double & triple word instructions
                        addr += (InstrLen(line) - 1)

    # Check that all labels used in arguments are in the labels table
    for lbl in undef_labels:
        if lbl not in labels:
            print(f"\nAssembly error -  No declaration for the label '{lbl}'", end='')
        
    # Re-adjust the labels table to account for any DC directives
    if numDCs > 0:
        v_adj = DC_GEN_CODES * numDCs
        for lbl in labels:
            v,d = labels[lbl]
            if not d:
                # Only adjust for non-directives
                v = int(v)
                v += v_adj
                labels[lbl] = (str(v),d)

    # 2nd pass through the assembly code - Produce the machine code
    lineNo = 0
    with open(fileIn,'r') as asm:
        with open(fileOut,'a') as mc:
            for line in asm:
                lineNo += 1
                line = line.upper().strip()

                # Ignore 'ORIGIN' directive
                if line.startswith('ORIGIN'):
                    continue

                # We're done if it's the 'STARTADDRESS' directive
                if line.startswith('STARTADDRESS'):
                    break

                # Ignore 'EQU' directives'
                elif line.startswith('EQU'):
                    continue

                # Ignore comments
                elif line.startswith(';'):
                    continue

                # Ignore inline comments
                line = line.split(';')
                line = line[0].strip()

                # Ignore blank lines and labels
                if len(line) != 0 and not line.endswith(':'):
                    # Remove label
                    if ':' in line:
                        line_parts = line.split(':')
                        label = line_parts[0].strip()
                        line = line_parts[1].strip()
                    
                    # Get the instruction & args 
                    line_parts = line.split(' ', 1)
                    instr = line_parts[0].strip()
                    if (instr not in instrs) and (instr not in condJumps):
                        raise SyntaxError(f'Unrecognised instruction: {instr}')
                    
                    # Deal with the the instructions that have no arguments
                    if instr in NO_ARGS_INSTRS:
                        if len(line_parts) > 1:
                            raise SyntaxError(f"'{instr}' doesn't take any arguments")
                        
                        bytes = GetInstrBytes(instr)
                        WriteWord(hex(bytes[0])[2:])
                        continue

                    # Deal with the the instructions that have arguments 
                    args = RemoveSpaces(line_parts[1])

                    # All conditional jumps are 'JUMPIF's
                    instr_copy = instr
                    if instr in condJumps:
                        instr_copy = 'JUMPIF'

                    fmt_list = instrs[instr_copy][INSTR_FORMATS]

                    # Replace any labels with their values
                    args_parts = args.split(',')
                    for i in range(len(args_parts)):
                        for lbl in labels:
                            # Test for arg being one of lbl, (lbl) & [lbl]
                            lbl_br = '(' + lbl + ')'
                            lbl_sb = '[' + lbl + ']'
                            if args_parts[i] in [lbl, lbl_br, lbl_sb]:
                                # Replace if it's in the 'label list'
                                val,_ = labels[lbl]
                                args_parts[i] = args_parts[i].replace(lbl, val)
                                break

                    args = ','.join(args_parts)

                    # Add the instruction bytes to the machine code file
                    bytes = GetInstrBytes(instr, args, fmt_list)

                    WriteWord(hex(bytes[0])[2:])

                    # If it's a 2 or 3 byte instruction add the extra bytes
                    if bytes[1] is not None:
                        WriteWord(hex(bytes[1])[2:])

                    if bytes[2] is not None:
                        WriteWord(hex(bytes[2])[2:])

    print('\nAssembly Successfull\n')

except FileNotFoundError:
    print(f'\nAssembly failed - File not found: {fileIn}\n')

except AssertionError as ae:
    DeleteFile(fileOut)
    print(f'\nAssembly failed - {ae.args[0]}\n')

except NameError as ne:
    DeleteFile(fileOut)
    print(f'\nAssembly failed - {ne.args[0]}\n')

except SyntaxError as se:
    DeleteFile(fileOut)
    print(f'\nAssembly failed - Syntax error at line {lineNo}: {se.args[0]}\n')
    
except Exception as e:
    DeleteFile(fileOut)
    print(e)
