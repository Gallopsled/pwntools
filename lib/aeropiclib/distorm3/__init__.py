# :[diStorm3}: Python binding
# Based on diStorm64 Python binding by Mario Vilas
# Initial support for decompose API added by Roee Shenberg
# Changed license to GPLv3.
#
# Compatible with Python2.6 and above.
#

info = (
    "diStorm3 by Gil Dabah, http://code.google.com/p/distorm/\n"
    "Based on diStorm64 Python binding by Mario Vilas, http://breakingcode.wordpress.com/\n"
)

__revision__ = "$Id: distorm.py 186 2010-05-01 14:20:41Z gdabah $"

__all__ = [
    'Decode',
    'DecodeGenerator',
    'Decompose',
    'DecomposeGenerator',
    'Decode16Bits',
    'Decode32Bits',
    'Decode64Bits',
    'Mnemonics',
    'Registers',
]

from ctypes import *
from os.path import split, join

#==============================================================================
# Load the diStorm DLL

# Guess the DLL filename and load the library.
_distorm_path = split(__file__)[0]
potential_libs = ['distorm3.dll', 'libdistorm3.dll', 'libdistorm3.so', 'libdistorm3.dylib']
lib_was_found = False
for i in potential_libs:
    try:
        _distorm_file = join(_distorm_path, i)
        _distorm = cdll.LoadLibrary(_distorm_file)
        lib_was_found = True
    except OSError:
        pass

if lib_was_found == False:
    raise ImportError("Error loading the diStorm dynamic library (or cannot load library into process).")

# Get the decode C function (try 64 bits version first, only then 32 bits).
SUPPORT_64BIT_OFFSET = False
try:
    internal_decode = _distorm.distorm_decode64
    internal_decompose = _distorm.distorm_decompose64
    internal_format = _distorm.distorm_format64
    SUPPORT_64BIT_OFFSET = True
except AttributeError:
    try:
          internal_decode = _distorm.distorm_decode32
          internal_decompose = _distorm.distorm_decompose32
          internal_format = _distorm.distorm_format32
    except AttributeError:
        raise ImportError("Error loading distorm")

#==============================================================================
# diStorm C interface

MAX_TEXT_SIZE       = 48 # See distorm.h for this value.
MAX_INSTRUCTIONS    = 1000

DECRES_NONE         = 0
DECRES_SUCCESS      = 1
DECRES_MEMORYERR    = 2
DECRES_INPUTERR     = 3

if SUPPORT_64BIT_OFFSET:
    _OffsetType = c_ulonglong
else:
    _OffsetType = c_uint

class _WString (Structure):
    _fields_ = [
        ('length',  c_uint),
        ('p',       c_char * MAX_TEXT_SIZE),
    ]

class _CodeInfo (Structure):
    _fields_ = [
        ('codeOffset',	_OffsetType),
        ('nextOffset',  _OffsetType),
        ('code',        c_char_p),
        ('codeLen',     c_int),
        ('dt',          c_byte),
        ('features',    c_uint),
        ]

class _DecodedInst (Structure):
    _fields_ = [
        ('mnemonic',        _WString),
        ('operands',        _WString),
        ('instructionHex',  _WString),
        ('size',            c_uint),
        ('offset',          _OffsetType),
    ]

# _OperandType enum
_OperandType = c_ubyte

O_NONE = 0
O_REG  = 1
O_IMM  = 2
O_IMM1 = 3
O_IMM2 = 4
O_DISP = 5
O_SMEM = 6
O_MEM  = 7
O_PC   = 8
O_PTR  = 9

class _Operand (Structure):
    _fields_ = [
        ('type',  c_ubyte), # of type _OperandType
        ('index', c_ubyte),
        ('size',  c_uint16),
    ]

class _ex (Structure):
    _fields_ = [
        ('i1', c_uint32),
        ('i2', c_uint32),
    ]
class _ptr (Structure):
    _fields_ = [
        ('seg', c_uint16),
        ('off', c_uint32),
    ]

class _Value (Union):
    _fields_ = [
        ('sbyte', c_byte),
        ('byte', c_ubyte),
        ('sword', c_int16),
        ('word', c_uint16),
        ('sdword', c_int32),
        ('dword', c_uint32),
        ('sqword', c_int64),
        ('qword', c_uint64),
        ('addr', _OffsetType),
        ('ptr', _ptr),
        ('ex', _ex),
        ]

class _DInst (Structure):
    _fields_ = [
        ('imm', _Value),
        ('disp', c_uint64),    # displacement. size is according to dispSize
        ('addr',  _OffsetType),
        ('flags',  c_uint16), # -1 if invalid. See C headers for more info
        ('unusedPrefixesMask', c_uint16),
        ('usedRegistersMask', c_uint16), # used registers mask.
        ('opcode', c_uint16),  # look up in opcode table
        ('ops', _Operand*4),
        ('size', c_ubyte),
        ('segment', c_ubyte), # -1 if unused. See C headers for more info
        ('base', c_ubyte),    # base register for indirections
        ('scale', c_ubyte),   # ignore for values 0, 1 (other valid values - 2,4,8)
        ('dispSize', c_ubyte),
        ('meta', c_ubyte), # meta flags - instruction set class, etc. See C headers again...
        ('modifiedFlagsMask', c_ubyte), # CPU modified (output) flags by instruction.
        ('testedFlagsMask', c_ubyte), # CPU tested (input) flags by instruction.
        ('undefinedFlagsMask', c_ubyte) # CPU undefined flags by instruction.
        ]

#==============================================================================
# diStorm Python interface

Decode16Bits    = 0     # 80286 decoding
Decode32Bits    = 1     # IA-32 decoding
Decode64Bits    = 2     # AMD64 decoding
OffsetTypeSize  = sizeof(_OffsetType)

Mnemonics = {0x669: "SLDT", 0x62: "POPA", 0x8ee: "UNPCKHPS", 0x115: "POPF", 0x11b9: "CMPLTSS",
0x85f: "VMOVSD", 0x789: "PFPNACC", 0xb14: "VMOVMSKPD", 0x737: "INVLPGA", 0x8f8: "UNPCKHPD",
0x270: "SYSEXIT", 0x7b2: "PFSUB", 0x1208: "CMPLTSD", 0x1a5d: "VPMULHUW", 0x1d35: "VPHSUBSW",
0x12b2: "VCMPNGEPS", 0x857: "VMOVSS", 0x6f: "ARPL", 0x52a: "FICOMP", 0x162: "RETF",
0x44d: "FCHS", 0x1124: "CMPLEPS", 0xef2: "PUNPCKHDQ", 0x2401: "VAESDEC", 0x5ee: "FUCOM",
0x129a: "VCMPORDPS", 0x19ab: "PSUBUSW", 0x1b45: "PXOR", 0x1e0f: "VPABSB", 0x24a: "WRMSR",
0x12a5: "VCMPEQ_UQPS", 0x22b6: "VFMADDSUB231PD", 0x7c9: "PFMAX", 0x16cd: "VCMPNEQ_OSSS",
0x2244: "VFNMADD213PD", 0x3b8: "MOVNTI", 0x7c0: "PFCMPGT", 0x236a: "VFNMADD231SS",
0x2450: "ROUNDPD", 0x12ed: "VCMPGTPS", 0xb9f: "VRCPSS", 0x213a: "VFNMADD132SS",
0x1444: "VCMPNGEPD", 0x220f: "VFMSUB213PD", 0x185f: "VCMPNEQ_OSSD", 0x267f: "VPSLLDQ",
0x792: "PFCMPGE", 0x147f: "VCMPGTPD", 0x1a83: "CVTDQ2PD", 0x1211: "CMPLESD",
0xae: "JNS", 0xdd8: "VDIVSD", 0xb7: "JNP", 0x2508: "EXTRACTPS", 0x1f43: "PMOVZXBQ",
0x9c: "JNZ", 0x5d8: "FCOMI", 0xee6: "VPUNPCKHWD", 0x1f2e: "PMOVZXBD", 0x1aca: "VMOVNTDQ",
0x1e74: "PMOVSXWD", 0x10f2: "POPCNT", 0x8a: "JNO", 0x1c8f: "FNSAVE", 0x1a5: "LOOP",
0xb09: "VMOVMSKPS", 0x46b: "FLDL2T", 0x12d: "CMPS", 0x408: "FSUB", 0xda4: "DIVPS",
0x1d1b: "PHSUBD", 0x11b0: "CMPEQSS", 0x1e7: "CMC", 0xcff: "CVTTPS2DQ", 0xdab: "DIVPD",
0xf5c: "VMOVD", 0x104: "CALL FAR", 0x1d72: "PMULHRSW", 0x1d7c: "VPMULHRSW",
0x1d0a: "PHSUBW", 0x11ff: "CMPEQSD", 0x3b2: "XADD", 0x2ae: "CMOVBE", 0x47: "CMP",
0x24: "SBB", 0x106e: "VHADDPS", 0x26ad: "FXRSTOR64", 0x2064: "INVVPID", 0x20f: "LSL",
0x165d: "VCMPNEQ_USSS", 0x1065: "VHADDPD", 0x38b: "LSS", 0x20f7: "VFMSUB132PD",
0x121: "LAHF", 0x7ec: "PFACC", 0x803: "PFRCPIT2", 0xe27: "VPUNPCKLBW", 0x7d0: "PFRCPIT1",
0x1f97: "PCMPGTQ", 0x49f: "FYL2X", 0x1819: "VCMPORD_SSD", 0x1933: "PSRLD",
0x10e1: "SFENCE", 0xcf5: "CVTPS2DQ", 0x24af: "PBLENDW", 0x21ae: "VFMSUBADD213PS",
0x2542: "VPINSRB", 0xe76: "PCMPGTB", 0xe9c: "PCMPGTD", 0x23d7: "VAESENC", 0x957: "VMOVSHDUP",
0x259c: "MPSADBW", 0x14e7: "VCMPNLE_UQPD", 0x70a: "VMMCALL", 0x102f: "INSERTQ",
0x2252: "VFNMADD213SS", 0x9bf: "CVTPI2PD", 0x16f: "INT", 0x1d87: "VPERMILPS",
0x1e2: "HLT", 0x2043: "PHMINPOSUW", 0x5b1: "FCMOVNU", 0x206d: "INVPCID", 0x7b: "INS",
0x647: "FCOMIP", 0x9b5: "CVTPI2PS", 0x2260: "VFNMADD213SD", 0xeaf: "PACKUSWB",
0xe4: "CBW", 0x71b: "VMSAVE", 0x10e: "PUSHF", 0x64f: "NOT", 0x595: "FCMOVNB",
0x245: "NOP", 0x4e8: "FSQRT", 0x1d92: "VPERMILPD", 0x51: "INC", 0x239: "UD2",
0xfe7: "VPCMPEQW", 0x2615: "PCMPISTRM", 0x1ecd: "VPCMPEQQ", 0x114d: "CMPNLEPS",
0x1826: "VCMPEQ_USSD", 0x13fe: "VCMPUNORDPD", 0x5fd: "FADDP", 0x145: "RET",
0xffa: "VPCMPEQD", 0x1fc3: "VPMINSD", 0xfd4: "VPCMPEQB", 0x18fa: "ADDSUBPD",
0x22a6: "VFMADDSUB231PS", 0x1694: "VCMPEQ_USSS", 0x1d50: "PSIGNW", 0x1ea8: "VPMOVSXDQ",
0x2007: "VPMAXSD", 0x35b: "SETG", 0x1ff6: "VPMAXSB", 0x327: "SETA", 0x306: "SETB",
0x26df: "STMXCSR", 0x347: "SETL", 0x20ea: "VFMSUB132PS", 0x2f9: "SETO", 0xbcd: "ANDNPD",
0x1106: "BSR", 0x8ba: "VMOVDDUP", 0x1b3c: "VPMAXSW", 0x1d61: "PSIGND", 0x33a: "SETP",
0x1d3f: "PSIGNB", 0x395: "LFS", 0x32d: "SETS", 0x1590: "VCMPUNORDSS", 0xbc5: "ANDNPS",
0x2716: "VMXON", 0xbb5: "VANDPS", 0x6f3: "XSETBV", 0x1c3: "OUT", 0x67a: "LTR",
0x2570: "VPINSRD", 0x10ff: "TZCNT", 0xa57: "VCVTTSS2SI", 0x266e: "VPSRLDQ",
0x4c6: "FDECSTP", 0x2666: "PSRLDQ", 0x186d: "VCMPGE_OQSD", 0x2677: "PSLLDQ",
0x50f: "FCOS", 0x4b5: "FXTRACT", 0x16db: "VCMPGE_OQSS", 0x1ee1: "VMOVNTDQA",
0x151d: "VCMPNGT_UQPD", 0x3f5: "FMUL", 0x13c4: "VCMPGT_OQPS", 0x60b: "FCOMPP",
0x77a: "PF2ID", 0xf5: "CWD", 0x132a: "VCMPUNORD_SPS", 0x2ea: "CMOVLE", 0xfb7: "VPSHUFHW",
0x1556: "VCMPGT_OQPD", 0x1ce0: "PHADDSW", 0x773: "PF2IW", 0xa21: "VMOVNTPD",
0x401: "FCOMP", 0x8c4: "UNPCKLPS", 0x1bcf: "MASKMOVDQU", 0x560: "FCMOVBE",
0x14a2: "VCMPLT_OQPD", 0xe14: "VMAXSD", 0x1416: "VCMPNLTPD", 0x987: "PREFETCHT2",
0x97b: "PREFETCHT1", 0x96f: "PREFETCHT0", 0x8ce: "UNPCKLPD", 0xa41: "CVTTSS2SI",
0x65e: "DIV", 0x1e9e: "PMOVSXDQ", 0x1607: "VCMPGESS", 0xef: "CDQE", 0x26f2: "VSTMXCSR",
0x539: "FISUBR", 0x1fb2: "VPMINSB", 0x2202: "VFMSUB213PS", 0x1310: "VCMPLT_OQPS",
0x11c2: "CMPLESS", 0x1afe: "VPMINSW", 0x1c5a: "FSTENV", 0x1799: "VCMPGESD",
0x1dd4: "VPTEST", 0x532: "FISUB", 0x205: "STD", 0xf13: "VPACKSSDW", 0x3d: "XOR",
0xc7f: "VMULPD", 0x1f1: "STC", 0x1fb: "STI", 0x26c2: "LDMXCSR", 0x116a: "CMPLTPD",
0xbe7: "ORPS", 0x1ef6: "VPACKUSDW", 0x61b: "FSUBP", 0x66f: "STR", 0x40e: "FSUBR",
0x111b: "CMPLTPS", 0x230d: "VFMADD231SD", 0x2725: "PAUSE", 0x1a8d: "CVTPD2DQ",
0x372: "RSM", 0xb5a: "VSQRTSD", 0xbf3: "VORPS", 0x218e: "VFMADDSUB213PS", 0x23cf: "AESENC",
0x1437: "VCMPEQ_UQPD", 0x902: "VUNPCKHPS", 0x1cf3: "PMADDUBSW", 0x1355: "VCMPNLE_UQPS",
0x1b68: "VPSLLW", 0x1bc5: "MASKMOVQ", 0x1c8: "CALL", 0xb51: "VSQRTSS", 0x19dc: "PADDUSB",
0x1020: "VMREAD", 0x10d5: "XSAVEOPT64", 0x90d: "VUNPCKHPD", 0xd48: "VSUBPS",
0xcd5: "VCVTSS2SD", 0x2416: "VAESDECLAST", 0x107f: "HSUBPS", 0xa97: "VCVTSS2SI",
0x25dc: "VPBLENDVB", 0x17a3: "VCMPGTSD", 0x57a: "FILD", 0xae3: "VCOMISS", 0x1077: "HSUBPD",
0x23a2: "VFNMSUB231SS", 0x1a3d: "VPSRAD", 0x128f: "VCMPNLEPS", 0x3e5: "SAL",
0x214: "SYSCALL", 0xb7f: "VRSQRTSS", 0x2579: "VPINSRQ", 0x26e8: "WRGSBASE",
0xfae: "VPSHUFD", 0x1e35: "PMOVSXBW", 0x1a2e: "VPSRAW", 0x1421: "VCMPNLEPD",
0x3ef: "FADD", 0x3ea: "SAR", 0x1ab9: "MOVNTQ", 0x2643: "AESKEYGENASSIST", 0xf09: "PACKSSDW",
0x21e8: "VFMADD213SS", 0xf7a: "VMOVDQA", 0x8af: "VMOVSLDUP", 0x4f8: "FRNDINT",
0x1960: "PMULLW", 0xdb9: "DIVSD", 0xaf5: "MOVMSKPS", 0x2018: "VPMAXUW", 0xdc8: "VDIVPD",
0x1e3f: "VPMOVSXBW", 0x1e89: "PMOVSXWQ", 0x2032: "PMULLD", 0xf83: "VMOVDQU",
0x2298: "VFNMSUB213SD", 0x297: "CMOVAE", 0x1495: "VCMPEQ_OSPD", 0xdc0: "VDIVPS",
0x93: "JAE", 0xaff: "MOVMSKPD", 0xdb2: "DIVSS", 0x1c97: "FSAVE", 0x1ec4: "PCMPEQQ",
0xfc1: "VPSHUFLW", 0xfde: "PCMPEQW", 0x26d5: "VLDMXCSR", 0x2104: "VFMSUB132SS",
0x11a6: "CMPORDPD", 0xb90: "RCPSS", 0x1b77: "VPSLLD", 0x663: "IDIV", 0x142c: "VCMPORDPD",
0xfcb: "PCMPEQB", 0xff1: "PCMPEQD", 0x1b86: "VPSLLQ", 0x1f4d: "VPMOVZXBQ",
0x21be: "VFMSUBADD213PD", 0x25d1: "VBLENDVPD", 0x1157: "CMPORDPS", 0xf1e: "PUNPCKLQDQ",
0x19d5: "VPAND", 0x1467: "VCMPNEQ_OQPD", 0x1055: "HADDPD", 0x1919: "VADDSUBPS",
0x18d1: "VSHUFPD", 0xd60: "VSUBSD", 0xb3f: "VSQRTPS", 0x931: "MOVSHDUP", 0x2378: "VFNMADD231SD",
0x6bf: "VMLAUNCH", 0x1f0d: "VMASKMOVPD", 0x105d: "HADDPS", 0x12d5: "VCMPNEQ_OQPS",
0xe33: "PUNPCKLWD", 0x16af: "VCMPNGT_UQSS", 0xb48: "VSQRTPD", 0xd58: "VSUBSS",
0x18c8: "VSHUFPS", 0x159d: "VCMPNEQSS", 0x1b59: "VLDDQU", 0x1634: "VCMPLT_OQSS",
0x26fc: "RDRAND", 0x1b23: "PADDSW", 0x1370: "VCMPEQ_USPS", 0xbed: "ORPD", 0x1a09: "PANDN",
0x4a6: "FPTAN", 0x541: "FIDIV", 0x17c6: "VCMPLT_OQSD", 0x2704: "VMPTRLD", 0x231a: "VFMSUB231PS",
0x172f: "VCMPNEQSD", 0x1ebb: "VPMULDQ", 0x196: "LOOPNZ", 0x126c: "VCMPUNORDPS",
0x3e0: "SHR", 0x37c: "SHRD", 0x6db: "MONITOR", 0x23e0: "AESENCLAST", 0x83e: "MOVSD",
0x189e: "VPINSRW", 0x713: "VMLOAD", 0x918: "MOVLHPS", 0x8a6: "VMOVLPD", 0x1971: "MOVQ2DQ",
0xb2f: "SQRTSS", 0x2588: "VDPPS", 0xd3a: "SUBSS", 0x3ab: "MOVSX", 0x93b: "VMOVLHPS",
0x89d: "VMOVLPS", 0xefd: "VPUNPCKHDQ", 0x1aae: "VCVTPD2DQ", 0x3db: "SHL", 0x837: "MOVSS",
0x2568: "PINSRQ", 0x781: "PFNACC", 0xf72: "MOVDQU", 0x80: "OUTS", 0x1be8: "PSUBB",
0x377: "BTS", 0x390: "BTR", 0x17ef: "VCMPNEQ_USSD", 0x68b: "SGDT", 0x2300: "VFMADD231SS",
0x501: "FSCALE", 0x1bf7: "PSUBW", 0x1192: "CMPNLTPD", 0x1eec: "PACKUSDW", 0x20a: "LAR",
0x3a6: "BTC", 0x2148: "VFNMADD132SD", 0x144f: "VCMPNGTPD", 0x1f23: "VPMOVZXBW",
0x2111: "VFMSUB132SD", 0x23be: "AESIMC", 0x3fb: "FCOM", 0x1f38: "VPMOVZXBD",
0x190e: "VADDSUBPD", 0x1c88: "FINIT", 0x11f5: "CMPORDSS", 0x231: "WBINVD",
0x19cf: "PAND", 0x24cb: "VPALIGNR", 0x1244: "CMPORDSD", 0x1b4b: "VPXOR", 0xa1: "JBE",
0x45f: "FXAM", 0x10cb: "XSAVEOPT", 0x659: "MUL", 0x19c6: "VPMINUB", 0x1b2b: "VPADDSW",
0x1b34: "PMAXSW", 0x2555: "VINSERTPS", 0x13e0: "VCMPEQPD", 0x5e7: "FFREE",
0x1f01: "VMASKMOVPS", 0x18da: "CMPXCHG8B", 0x1fff: "PMAXSD", 0x1b1a: "VPADDSB",
0x10: "PUSH", 0x25ba: "VPCLMULQDQ", 0x124e: "VCMPEQPS", 0x7da: "PFRSQIT1",
0x243d: "ROUNDPS", 0x2ff: "SETNO", 0x6eb: "XGETBV", 0x1fbb: "PMINSD", 0x1c24: "PADDB",
0x4be: "FPREM1", 0x200: "CLD", 0x51c: "FIMUL", 0xc08: "XORPD", 0x1ec: "CLC",
0x42c: "FSTP", 0x249c: "BLENDPD", 0x19ef: "PADDUSW", 0x1c80: "FNINIT", 0x319: "SETNZ",
0x1951: "PADDQ", 0xc01: "XORPS", 0x228a: "VFNMSUB213SS", 0x333: "SETNS", 0x515: "FIADD",
0x340: "SETNP", 0xf43: "VPUNPCKHQDQ", 0xd2c: "SUBPS", 0x1230: "CMPNLTSD", 0x674: "LLDT",
0x2229: "VFMSUB213SD", 0x1dcd: "PTEST", 0x2164: "VFNMSUB132PD", 0x279: "GETSEC",
0x1d69: "VPSIGND", 0x1ab: "JCXZ", 0x11e1: "CMPNLTSS", 0x34d: "SETGE", 0x1112: "CMPEQPS",
0x1bb4: "PSADBW", 0x271d: "MOVSXD", 0x2156: "VFNMSUB132PS", 0x185: "AAD", 0x23ec: "VAESENCLAST",
0xf37: "PUNPCKHQDQ", 0x878: "MOVLPD", 0x19e5: "VPADDUSW", 0x12c8: "VCMPFALSEPS",
0x180: "AAM", 0xf2a: "VPUNPCKLQDQ", 0xd76: "MINSS", 0x1c42: "PADDD", 0x145a: "VCMPFALSEPD",
0xe3e: "VPUNPCKLWD", 0x870: "MOVLPS", 0x729: "CLGI", 0x4c: "AAS", 0x139: "LODS",
0x2d3: "CMOVNP", 0xd7d: "MINSD", 0x1f6: "CLI", 0xa4c: "CVTTSD2SI", 0x523: "FICOM",
0x1f19: "PMOVZXBW", 0xc26: "ADDPD", 0x75a: "PREFETCHW", 0x1339: "VCMPNEQ_USPS",
0xc17: "VXORPD", 0x1b07: "POR", 0x16: "POP", 0x2431: "VPERM2F128", 0x19e: "LOOPZ",
0x1ac1: "MOVNTDQ", 0x1dc: "INT1", 0x382: "CMPXCHG", 0x1df8: "VBROADCASTF128",
0x150f: "VCMPNGE_UQPD", 0x1cbe: "PHADDW", 0xc0f: "VXORPS", 0x14cb: "VCMPNEQ_USPD",
0xc1f: "ADDPS", 0x7fc: "PFMUL", 0x697: "LGDT", 0x67f: "VERR", 0x685: "VERW",
0x1087: "VHSUBPD", 0x1968: "VPMULLW", 0x845: "VMOVUPS", 0x174: "INTO", 0x1c79: "FCLEX",
0x1090: "VHSUBPS", 0xcb5: "CVTSD2SS", 0x47b: "FLDPI", 0x1e17: "PABSW", 0xe04: "VMAXPD",
0x1d3: "JMP FAR", 0xeb9: "VPACKUSWB", 0x571: "FUCOMPP", 0x84e: "VMOVUPD", 0x816: "PSWAPD",
0x247f: "VROUNDSD", 0x1c33: "PADDW", 0x1b70: "PSLLD", 0x740: "SWAPGS", 0x880: "MOVSLDUP",
0x9c9: "CVTSI2SS", 0x17ad: "VCMPTRUESD", 0x11cb: "CMPUNORDSS", 0xd20: "VCVTTPS2DQ",
0xb37: "SQRTSD", 0x1dea: "VBROADCASTSD", 0x1c06: "PSUBD", 0xce: "TEST", 0x39a: "LGS",
0x161b: "VCMPTRUESS", 0x266: "SYSENTER", 0x9d3: "CVTSI2SD", 0x1745: "VCMPNLESD",
0x1da6: "VTESTPD", 0x98: "JZ", 0xdd0: "VDIVSS", 0xbfa: "VORPD", 0xb3: "JP",
0xaa: "JS", 0xbc: "JL", 0xb6c: "RSQRTSS", 0x1d9d: "VTESTPS", 0x86: "JO", 0xdfc: "VMAXPS",
0x1998: "PSUBUSB", 0xca: "JG", 0x1ddc: "VBROADCASTSS", 0xa6: "JA", 0x8f: "JB",
0xe9: "CWDE", 0x13f4: "VCMPLEPD", 0x1038: "VMWRITE", 0x1262: "VCMPLEPS", 0x1983: "PMOVMSKB",
0x254b: "INSERTPS", 0x25fe: "PCMPESTRI", 0x272c: "WAIT", 0x152b: "VCMPFALSE_OSPD",
0x25e7: "PCMPESTRM", 0xe4a: "PUNPCKLDQ", 0xc69: "MULSS", 0xd50: "VSUBPD", 0x1161: "CMPEQPD",
0x178b: "VCMPNEQ_OQSD", 0xaec: "VCOMISD", 0xd94: "VMINSS", 0x1c49: "VPADDD",
0x258: "RDMSR", 0x1d58: "VPSIGNW", 0x1b1: "JECXZ", 0xc70: "MULSD", 0x154: "ENTER",
0x2423: "MOVBE", 0x1016: "VZEROALL", 0x2732: "_3DNOW", 0xd9c: "VMINSD", 0x15f9: "VCMPNEQ_OQSS",
0x7e4: "PFSUBR", 0x12e3: "VCMPGEPS", 0x19a1: "VPSUBUSB", 0x2341: "VFMSUB231SD",
0x2021: "PMAXUD", 0x2688: "FXSAVE", 0x580: "FISTTP", 0x1475: "VCMPGEPD", 0x2489: "BLENDPS",
0x1718: "VCMPLESD", 0x5a7: "FCMOVNBE", 0x2334: "VFMSUB231SS", 0x25c6: "VBLENDVPS",
0x25a5: "VMPSADBW", 0x19b4: "VPSUBUSW", 0x170e: "VCMPLTSD", 0x1ed7: "MOVNTDQA",
0x18c0: "SHUFPD", 0xd33: "SUBPD", 0xb27: "SQRTPD", 0x94e: "VMOVHPD", 0x6b7: "VMCALL",
0x20c3: "VFMADD132PD", 0x15b: "LEAVE", 0x18b8: "SHUFPS", 0x1303: "VCMPEQ_OSPS",
0x2609: "VPCMPESTRI", 0x157c: "VCMPLTSS", 0x25f2: "VPCMPESTRM", 0x20b6: "VFMADD132PS",
0x69d: "LIDT", 0x498: "F2XM1", 0x945: "VMOVHPS", 0x1f82: "PMOVZXDQ", 0x100a: "VZEROUPPER",
0xb1f: "SQRTPS", 0xbd5: "VANDNPS", 0x1958: "VPADDQ", 0x4d8: "FPREM", 0x1c3a: "VPADDW",
0x24c2: "PALIGNR", 0x1faa: "PMINSB", 0xe89: "PCMPGTW", 0x36c: "SHLD", 0x14f: "LDS",
0x1c2b: "VPADDB", 0x703: "VMRUN", 0x269a: "RDFSBASE", 0xbde: "VANDNPD", 0x190: "XLAT",
0xd4: "XCHG", 0x4cf: "FINCSTP", 0x197a: "MOVDQ2Q", 0x1af6: "PMINSW", 0x6a3: "SMSW",
0x1d47: "VPSIGNB", 0x10b1: "XRSTOR", 0x24a5: "VBLENDPD", 0xc0: "JGE", 0x1347: "VCMPNLT_UQPS",
0x1750: "VCMPORDSD", 0x2492: "VBLENDPS", 0x459: "FTST", 0x1a78: "CVTTPD2DQ",
0x15be: "VCMPORDSS", 0x14d9: "VCMPNLT_UQPD", 0x2172: "VFNMSUB132SS", 0x10b9: "XRSTOR64",
0x29: "AND", 0xb75: "VRSQRTPS", 0x10e9: "CLFLUSH", 0x1cad: "PSHUFB", 0x432: "FLDENV",
0xda: "MOV", 0xf94: "PSHUFD", 0xc5: "JLE", 0x5c0: "FEDISI", 0x6fb: "VMFUNC",
0xe92: "VPCMPGTW", 0x7f3: "PFCMPEQ", 0x1687: "VCMPORD_SSS", 0xf8c: "PSHUFW",
0x24dd: "VPEXTRB", 0x1aa3: "VCVTDQ2PD", 0xf63: "VMOVQ", 0x473: "FLDL2E", 0x24f6: "VPEXTRD",
0x1d12: "VPHSUBW", 0x226e: "VFNMSUB213PS", 0x21db: "VFMADD213PD", 0x723: "STGI",
0x4ad: "FPATAN", 0x24ff: "VPEXTRQ", 0x427: "FST", 0x168: "INT 3", 0x588: "FIST",
0x270d: "VMCLEAR", 0x1e5f: "PMOVSXBQ", 0x42: "AAA", 0x1d23: "VPHSUBD", 0xa2b: "CVTTPS2PI",
0x1139: "CMPNEQPS", 0x1549: "VCMPGE_OQPD", 0x1b52: "LDDQU", 0xb63: "RSQRTPS",
0xc43: "VADDPD", 0x7a2: "PFRCP", 0xcab: "CVTSS2SD", 0x2180: "VFNMSUB132SD",
0x622: "FDIVRP", 0x631: "FBLD", 0x361: "CPUID", 0x251: "RDTSC", 0x24b8: "VPBLENDW",
0xd15: "VCVTPS2DQ", 0x1b0c: "VPOR", 0xc3b: "VADDPS", 0x765: "PI2FW", 0xd68: "MINPS",
0x17b9: "VCMPEQ_OSSD", 0x1b97: "VPMULUDQ", 0xdf5: "MAXSD", 0x203a: "VPMULLD",
0x548: "FIDIVR", 0xabf: "VUCOMISS", 0x88a: "MOVDDUP", 0x1cb5: "VPSHUFB", 0x1d2c: "PHSUBSW",
0x2637: "VPCMPISTRI", 0xdee: "MAXSS", 0x1a1f: "VPAVGB", 0x16bd: "VCMPFALSE_OSSS",
0xd6f: "MINPD", 0x4df: "FYL2XP1", 0xac9: "VUCOMISD", 0x2394: "VFNMSUB231PD",
0x1833: "VCMPNGE_UQSD", 0xc34: "ADDSD", 0x6d3: "VMXOFF", 0x1942: "PSRLQ", 0x1279: "VCMPNEQPS",
0x1924: "PSRLW", 0x1a36: "PSRAD", 0x691: "SIDT", 0xe61: "PACKSSWB", 0x1099: "XSAVE",
0x140b: "VCMPNEQPD", 0xfa: "CDQ", 0xc2d: "ADDSS", 0x16a1: "VCMPNGE_UQSS", 0x242a: "CRC32",
0x23c6: "VAESIMC", 0x1fee: "PMAXSB", 0x2513: "VEXTRACTPS", 0x17fd: "VCMPNLT_UQSD",
0x1bef: "VPSUBB", 0x1f77: "VPMOVZXWQ", 0x13a9: "VCMPNEQ_OSPS", 0xa05: "MOVNTSS",
0x252c: "VEXTRACTF128", 0x1b12: "PADDSB", 0x75: "IMUL", 0x3d6: "RCR", 0x14bc: "VCMPUNORD_SPD",
0x3d1: "RCL", 0xa0e: "MOVNTSD", 0x153b: "VCMPNEQ_OSPD", 0x166b: "VCMPNLT_UQSS",
0xd41: "SUBSD", 0x13f: "SCAS", 0x25af: "PCLMULQDQ", 0x7a9: "PFRSQRT", 0x2560: "PINSRD",
0x613: "FSUBRP", 0x5b: "PUSHA", 0x1a00: "VPMAXUB", 0x112d: "CMPUNORDPS", 0x2029: "VPMAXUD",
0x453: "FABS", 0x1e69: "VPMOVSXBQ", 0x1489: "VCMPTRUEPD", 0x23e: "FEMMS", 0x1627: "VCMPEQ_OSSS",
0x21f5: "VFMADD213SD", 0x1e54: "VPMOVSXBD", 0x117c: "CMPUNORDPD", 0x18f1: "VMPTRST",
0x18e5: "CMPXCHG16B", 0x12f7: "VCMPTRUEPS", 0x12bd: "VCMPNGTPS", 0x1c71: "FNCLEX",
0x1226: "CMPNEQSD", 0x175b: "VCMPEQ_UQSD", 0x569: "FCMOVU", 0x1028: "EXTRQ",
0x258f: "DPPD", 0x2e2: "CMOVGE", 0x253a: "PINSRB", 0x15c9: "VCMPEQ_UQSS", 0x1cfe: "VPMADDUBSW",
0x11d7: "CMPNEQSS", 0x22f3: "VFMADD231PD", 0x509: "FSIN", 0x1bf: "IN", 0x558: "FCMOVE",
0x43a: "FLDCW", 0x2582: "DPPS", 0x550: "FCMOVB", 0x192b: "VPSRLW", 0x10a9: "LFENCE",
0xa8d: "CVTSD2SI", 0x30c: "SETAE", 0x2a6: "CMOVNZ", 0x1949: "VPSRLQ", 0x604: "FMULP",
0x9ac: "VMOVAPD", 0x1641: "VCMPLE_OQSS", 0x2c4: "CMOVNS", 0x59e: "FCMOVNE",
0x288: "CMOVNO", 0x1a6f: "VPMULHW", 0x193a: "VPSRLD", 0x104b: "CVTPS2PH", 0xa6f: "CVTPS2PI",
0x1ccf: "PHADDD", 0xc97: "CVTPS2PD", 0x1e1e: "VPABSW", 0x17d3: "VCMPLE_OQSD",
0x9a3: "VMOVAPS", 0x1bfe: "VPSUBW", 0x80d: "PMULHRW", 0x993: "MOVAPS", 0x79b: "PFMIN",
0xf50: "MOVD", 0x921: "MOVHPS", 0xc5b: "MULPS", 0x1258: "VCMPLTPS", 0x368: "BT",
0x99b: "MOVAPD", 0x137d: "VCMPNGE_UQPS", 0x1b8: "JRCXZ", 0xc62: "MULPD", 0x127: "MOVS",
0x6af: "INVLPG", 0xf56: "MOVQ", 0xd8c: "VMINPD", 0x1e26: "PABSD", 0x11b: "SAHF",
0x13d1: "VCMPTRUE_USPS", 0x76c: "PI2FD", 0x1e08: "PABSB", 0x1a10: "VPANDN",
0xe55: "VPUNPCKLDQ", 0x62a: "FDIVP", 0x1c15: "PSUBQ", 0x41b: "FDIVR", 0x415: "FDIV",
0x1563: "VCMPTRUE_USPD", 0x750: "PREFETCH", 0x1004: "EMMS", 0xd84: "VMINPS",
0x22e6: "VFMADD231PS", 0x227c: "VFNMSUB213PD", 0xa83: "CVTSS2SI", 0x929: "MOVHPD",
0x29f: "CMOVZ", 0x1a4c: "VPAVGW", 0xff: "CQO", 0x1c0d: "VPSUBD", 0x2cc: "CMOVP",
0x1572: "VCMPEQSS", 0x2bd: "CMOVS", 0x1e4a: "PMOVSXBD", 0x246c: "VROUNDSS",
0x1c1c: "VPSUBQ", 0x2db: "CMOVL", 0x1904: "ADDSUBPS", 0x281: "CMOVO", 0x2b6: "CMOVA",
0x290: "CMOVB", 0xec4: "PUNPCKHBW", 0x262c: "PCMPISTRI", 0x2f2: "CMOVG", 0x198d: "VPMOVMSKB",
0x240a: "AESDECLAST", 0x82f: "MOVUPD", 0x20a6: "VFMSUBADD132PD", 0x1bbc: "VPSADBW",
0x2459: "VROUNDPD", 0x6a9: "LMSW", 0x205c: "INVEPT", 0x39f: "MOVZX", 0xba7: "ANDPS",
0x2096: "VFMSUBADD132PS", 0x827: "MOVUPS", 0x1611: "VCMPGTSS", 0x1a54: "PMULHUW",
0x2595: "VDPPD", 0x24e6: "PEXTRD", 0x15ec: "VCMPFALSESS", 0x26b8: "RDGSBASE",
0x1b: "OR", 0x18af: "VPEXTRW", 0x1adc: "VPSUBSB", 0x26a4: "FXRSTOR", 0x21d: "CLTS",
0x1841: "VCMPNGT_UQSD", 0x15e1: "VCMPNGTSS", 0x5df: "FRSTOR", 0x177e: "VCMPFALSESD",
0x48a: "FLDLN2", 0x251f: "VINSERTF128", 0x1aed: "VPSUBSW", 0x1b8e: "PMULUDQ",
0x56: "DEC", 0x1399: "VCMPFALSE_OSPS", 0x422: "FLD", 0x1f8c: "VPMOVZXDQ", 0x2463: "ROUNDSS",
0x9dd: "VCVTSI2SS", 0x18a7: "PEXTRW", 0x2690: "FXSAVE64", 0x3c7: "ROL", 0x20dd: "VFMADD132SD",
0x1173: "CMPLEPD", 0xce0: "VCVTSD2SS", 0x5f5: "FUCOMP", 0x1ce: "JMP", 0x1704: "VCMPEQSD",
0xceb: "CVTDQ2PS", 0x16e8: "VCMPGT_OQSS", 0x5d0: "FUCOMI", 0x110b: "LZCNT",
0xb97: "VRCPPS", 0x19f8: "PMAXUB", 0x1cd7: "VPHADDD", 0x9e8: "VCVTSI2SD", 0x187a: "VCMPGT_OQSD",
0x3cc: "ROR", 0x22b: "INVD", 0xaa2: "VCVTSD2SI", 0x23f9: "AESDEC", 0x123a: "CMPNLESD",
0x354: "SETLE", 0x22c6: "VFMSUBADD231PS", 0x234e: "VFNMADD231PS", 0x10a0: "XSAVE64",
0xedb: "PUNPCKHWD", 0x1e7e: "VPMOVSXWD", 0xca1: "CVTPD2PS", 0x893: "VMOVHLPS",
0x22d6: "VFMSUBADD231PD", 0xa79: "CVTPD2PI", 0x11eb: "CMPNLESS", 0x1eb3: "PMULDQ",
0x1e93: "VPMOVSXWQ", 0x173a: "VCMPNLTSD", 0x235c: "VFNMADD231PD", 0x1ca6: "FSTSW",
0x748: "RDTSCP", 0x10c3: "MFENCE", 0x20d0: "VFMADD132SS", 0x1fdd: "PMINUD",
0x5ba: "FENI", 0x68: "BOUND", 0x2446: "VROUNDPS", 0xfa5: "PSHUFLW", 0xc87: "VMULSS",
0x184f: "VCMPFALSE_OSSD", 0xd0a: "VCVTDQ2PS", 0x1586: "VCMPLESS", 0x447: "FNOP",
0x1143: "CMPNLTPS", 0x1284: "VCMPNLTPS", 0x482: "FLDLG2", 0x223: "SYSRET",
0x1c6a: "FSTCW", 0x221c: "VFMSUB213SS", 0x72f: "SKINIT", 0xbbd: "VANDPD", 0x492: "FLDZ",
0x33: "SUB", 0x1cc6: "VPHADDW", 0x654: "NEG", 0x1fcc: "PMINUW", 0xde7: "MAXPD",
0x1363: "VCMPORD_SPS", 0x133: "STOS", 0x23b0: "VFNMSUB231SD", 0x1722: "VCMPUNORDSD",
0x81e: "PAVGUSB", 0x14f5: "VCMPORD_SPD", 0xde0: "MAXPS", 0x19be: "PMINUB",
0x1bdb: "VMASKMOVDQU", 0x637: "FBSTP", 0x1896: "PINSRW", 0x1f62: "VPMOVZXWD",
0x1fd4: "VPMINUW", 0x180b: "VCMPNLE_UQSD", 0x18a: "SALC", 0x24d5: "PEXTRB",
0x8d8: "VUNPCKLPS", 0x1679: "VCMPNLE_UQSS", 0xf6a: "MOVDQA", 0x15a8: "VCMPNLTSS",
0x1b7f: "PSLLQ", 0xa17: "VMOVNTPS", 0x1fe5: "VPMINUD", 0x962: "PREFETCHNTA",
0x8e3: "VUNPCKLPD", 0x1041: "CVTPH2PS", 0x2654: "VAESKEYGENASSIST", 0x1ae5: "PSUBSW",
0x1768: "VCMPNGESD", 0x1c51: "FNSTENV", 0x1c9e: "FNSTSW", 0x1188: "CMPNEQPD",
0x1a45: "PAVGW", 0x9fc: "MOVNTPD", 0x1502: "VCMPEQ_USPD", 0x5c8: "FSETPM",
0x1db9: "BLENDVPS", 0x219e: "VFMADDSUB213PD", 0xb: "ADD", 0x15d6: "VCMPNGESS",
0x1f: "ADC", 0x1ad4: "PSUBSB", 0x1dc3: "BLENDVPD", 0xecf: "VPUNPCKHBW", 0x25f: "RDPMC",
0x9f3: "MOVNTPS", 0x10fa: "BSF", 0x13ea: "VCMPLTPD", 0x1a18: "PAVGB", 0xdf: "LEA",
0x1a97: "VCVTTPD2DQ", 0xe7f: "VPCMPGTB", 0xea5: "VPCMPGTD", 0x465: "FLD1",
0x1baa: "VPMADDWD", 0x17e0: "VCMPUNORD_SSD", 0x14a: "LES", 0x313: "SETZ", 0x1fa0: "VPCMPGTQ",
0xc8f: "VMULSD", 0x21ce: "VFMADD213PS", 0x15b3: "VCMPNLESS", 0x867: "MOVHLPS",
0x204f: "VPHMINPOSUW", 0x1e2d: "VPABSD", 0x1a27: "PSRAW", 0x7b9: "PFADD", 0x2086: "VFMADDSUB132PD",
0xadb: "COMISD", 0x13b7: "VCMPGE_OQPS", 0xe0c: "VMAXSS", 0x121a: "CMPUNORDSD",
0x4ef: "FSINCOS", 0xad3: "COMISS", 0x2076: "VFMADDSUB132PS", 0xb89: "RCPPS",
0x212c: "VFNMADD132PD", 0x441: "FXCH", 0x2e: "DAA", 0x320: "SETBE", 0xcbf: "VCVTPS2PD",
0x1ba1: "PMADDWD", 0xbae: "ANDPD", 0x131d: "VCMPLE_OQPS", 0x1773: "VCMPNGTSD",
0x2386: "VFNMSUB231PS", 0x63e: "FUCOMIP", 0xc77: "VMULPS", 0x211e: "VFNMADD132PS",
0x26cb: "WRFSBASE", 0x38: "DAS", 0x14af: "VCMPLE_OQPD", 0x17a: "IRET", 0x3c0: "BSWAP",
0xe1c: "PUNPCKLBW", 0x2010: "PMAXUW", 0x2620: "VPCMPISTRM", 0x1b61: "PSLLW",
0x164e: "VCMPUNORD_SSS", 0x2236: "VFNMADD213PS", 0xa63: "VCVTTSD2SI", 0x2327: "VFMSUB231PD",
0x138b: "VCMPNGT_UQPS", 0x1c62: "FNSTCW", 0x2476: "ROUNDSD", 0x119c: "CMPNLEPD",
0x24ee: "PEXTRQ", 0x1a67: "PMULHW", 0x1ce9: "VPHADDSW", 0x58e: "FISTP", 0x1f6d: "PMOVZXWQ",
0xcca: "VCVTPD2PS", 0x16f5: "VCMPTRUE_USSS", 0xc53: "VADDSD", 0x1daf: "PBLENDVB",
0x6c9: "VMRESUME", 0xab6: "UCOMISD", 0x1f58: "PMOVZXWD", 0xa36: "CVTTPD2PI",
0xaad: "UCOMISS", 0xe6b: "VPACKSSWB", 0xc4b: "VADDSS", 0xf9c: "PSHUFHW", 0x1887: "VCMPTRUE_USSD",
0x6e4: "MWAIT"
}

Registers = ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D",
"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI", "R8W", "R9W", "R10W", "R11W", "R12W", "R13W", "R14W", "R15W",
"AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH", "R8B", "R9B", "R10B", "R11B", "R12B", "R13B", "R14B", "R15B",
"SPL", "BPL", "SIL", "DIL",
"ES", "CS", "SS", "DS", "FS", "GS",
"RIP",
"ST0", "ST1", "ST2", "ST3", "ST4", "ST5", "ST6", "ST7",
"MM0", "MM1", "MM2", "MM3", "MM4", "MM5", "MM6", "MM7",
"XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7", "XMM8", "XMM9", "XMM10", "XMM11", "XMM12", "XMM13", "XMM14", "XMM15",
"YMM0", "YMM1", "YMM2", "YMM3", "YMM4", "YMM5", "YMM6", "YMM7", "YMM8", "YMM9", "YMM10", "YMM11", "YMM12", "YMM13", "YMM14", "YMM15",
"CR0", "", "CR2", "CR3", "CR4", "", "", "", "CR8",
"DR0", "DR1", "DR2", "DR3", "", "", "DR6", "DR7"]

# Special case
R_NONE = 0xFF # -1 in uint8


FLAGS = [
# The instruction locks memory access.
"FLAG_LOCK",
# The instruction is prefixed with a REPNZ.
"FLAG_REPNZ",
# The instruction is prefixed with a REP, this can be a REPZ, it depends on the specific instruction.
"FLAG_REP",
# Indicates there is a hint taken for Jcc instructions only.
"FLAG_HINT_TAKEN",
# Indicates there is a hint non-taken for Jcc instructions only.
"FLAG_HINT_NOT_TAKEN",
# The Imm value is signed extended.
"FLAG_IMM_SIGNED",
# The destination operand is writable.
"FLAG_DST_WR",
# The instruction uses the RIP-relative indirection.
"FLAG_RIP_RELATIVE"
]

# Instruction could not be disassembled. Special-case handling
FLAG_NOT_DECODABLE = 0xFFFF # -1 in uint16
# Some features
DF_NONE = 0
DF_MAXIMUM_ADDR16 = 1
DF_MAXIMUM_ADDR32 = 2
DF_RETURN_FC_ONLY = 4
# Flow control flags
DF_STOP_ON_CALL = 0x8
DF_STOP_ON_RET  = 0x10
DF_STOP_ON_SYS  = 0x20
DF_STOP_ON_UNC_BRANCH  = 0x40
DF_STOP_ON_CND_BRANCH  = 0x80
DF_STOP_ON_INT  = 0x100
DF_STOP_ON_CMOV  = 0x200
DF_STOP_ON_FLOW_CONTROL = (DF_STOP_ON_CALL | DF_STOP_ON_RET | DF_STOP_ON_SYS | \
	DF_STOP_ON_UNC_BRANCH | DF_STOP_ON_CND_BRANCH | DF_STOP_ON_INT | DF_STOP_ON_CMOV)

def DecodeGenerator(codeOffset, code, dt):
    """
    @type  codeOffset: long
    @param codeOffset: Memory address where the code is located.
        This is B{not} an offset into the code!
        It's the actual memory address where it was read from.

    @type  code: str
    @param code: Code to disassemble.

    @type  dt: int
    @param dt: Disassembly type. Can be one of the following:

         * L{Decode16Bits}: 80286 decoding

         * L{Decode32Bits}: IA-32 decoding

         * L{Decode64Bits}: AMD64 decoding

    @rtype:  generator of tuple( long, int, str, str )
    @return: Generator of tuples. Each tuple represents an assembly instruction
        and contains:
         - Memory address of instruction.
         - Size of instruction in bytes.
         - Disassembly line of instruction.
         - Hexadecimal dump of instruction.

    @raise ValueError: Invalid arguments.
    """

    if not code:
        return

    if not codeOffset:
        codeOffset = 0

    if dt not in (Decode16Bits, Decode32Bits, Decode64Bits):
        raise ValueError("Invalid decode type value: %r" % (dt,))

    codeLen         = len(code)
    code_buf        = create_string_buffer(code)
    p_code          = byref(code_buf)
    result          = (_DecodedInst * MAX_INSTRUCTIONS)()
    p_result        = byref(result)
    instruction_off = 0

    while codeLen > 0:

        usedInstructionsCount = c_uint(0)
        status = internal_decode(_OffsetType(codeOffset), p_code, codeLen, dt, p_result, MAX_INSTRUCTIONS, byref(usedInstructionsCount))

        if status == DECRES_INPUTERR:
            raise ValueError("Invalid arguments passed to distorm_decode()")

        used = usedInstructionsCount.value
        if not used:
            break

        for index in xrange(used):
            di   = result[index]
            asm  = di.mnemonic.p
            if len(di.operands.p):
                asm += " " + di.operands.p
            pydi = (di.offset, di.size, asm, di.instructionHex.p)
            instruction_off += di.size
            yield pydi

        di         = result[used - 1]
        delta      = di.offset - codeOffset + result[used - 1].size
        if delta <= 0:
            break
        codeOffset = codeOffset + delta
        p_code     = byref(code_buf, instruction_off)
        codeLen    = codeLen - delta

def Decode(offset, code, type = Decode32Bits):
    """
    @type  offset: long
    @param offset: Memory address where the code is located.
        This is B{not} an offset into the code!
        It's the actual memory address where it was read from.

    @type  code: str
    @param code: Code to disassemble.

    @type  type: int
    @param type: Disassembly type. Can be one of the following:

         * L{Decode16Bits}: 80286 decoding

         * L{Decode32Bits}: IA-32 decoding

         * L{Decode64Bits}: AMD64 decoding

    @rtype:  list of tuple( long, int, str, str )
    @return: List of tuples. Each tuple represents an assembly instruction
        and contains:
         - Memory address of instruction.
         - Size of instruction in bytes.
         - Disassembly line of instruction.
         - Hexadecimal dump of instruction.

    @raise ValueError: Invalid arguments.
    """
    return list(DecodeGenerator(offset, code, type))

OPERAND_NONE = ""
OPERAND_IMMEDIATE = "Immediate"
OPERAND_REGISTER = "Register"

# the operand is a memory address
OPERAND_ABSOLUTE_ADDRESS = "AbsoluteMemoryAddress" # The address calculated is absolute
OPERAND_MEMORY = "AbsoluteMemory" # The address calculated uses registers expression
OPERAND_FAR_MEMORY = "FarMemory" # like absolute but with selector/segment specified too

InstructionSetClasses = [
"ISC_UNKNOWN",
# Indicates the instruction belongs to the General Integer set.
"ISC_INTEGER",
# Indicates the instruction belongs to the 387 FPU set.
"ISC_FPU",
# Indicates the instruction belongs to the P6 set.
"ISC_P6",
# Indicates the instruction belongs to the MMX set.
"ISC_MMX",
# Indicates the instruction belongs to the SSE set.
"ISC_SSE",
# Indicates the instruction belongs to the SSE2 set.
"ISC_SSE2",
# Indicates the instruction belongs to the SSE3 set.
"ISC_SSE3",
# Indicates the instruction belongs to the SSSE3 set.
"ISC_SSSE3",
# Indicates the instruction belongs to the SSE4.1 set.
"ISC_SSE4_1",
# Indicates the instruction belongs to the SSE4.2 set.
"ISC_SSE4_2",
# Indicates the instruction belongs to the AMD's SSE4.A set.
"ISC_SSE4_A",
# Indicates the instruction belongs to the 3DNow! set.
"ISC_3DNOW",
# Indicates the instruction belongs to the 3DNow! Extensions set.
"ISC_3DNOWEXT",
# Indicates the instruction belongs to the VMX (Intel) set.
"ISC_VMX",
# Indicates the instruction belongs to the SVM (AMD) set.
"ISC_SVM",
# Indicates the instruction belongs to the AVX (Intel) set.
"ISC_AVX",
# Indicates the instruction belongs to the FMA (Intel) set.
"ISC_FMA",
# Indicates the instruction belongs to the AES/AVX (Intel) set.
"ISC_AES",
# Indicates the instruction belongs to the CLMUL (Intel) set.
"ISC_CLMUL",
]

FlowControlFlags = [
# Indicates the instruction is not a flow-control instruction.
"FC_NONE",
# Indicates the instruction is one of: CALL, CALL FAR.
"FC_CALL",
# Indicates the instruction is one of: RET, IRET, RETF.
"FC_RET",
# Indicates the instruction is one of: SYSCALL, SYSRET, SYSENTER, SYSEXIT.
"FC_SYS",
# Indicates the instruction is one of: JMP, JMP FAR.
"FC_UNC_BRANCH",
# Indicates the instruction is one of:
# JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ.
"FC_CND_BRANCH",
# Indiciates the instruction is one of: INT, INT1, INT 3, INTO, UD2.
"FC_INT",
# Indicates the instruction is one of: CMOVxx.
"FC_CMOV"
]

def _getOpSize(flags):
    return ((flags >> 7) & 3)

def _getISC(metaflags):
    realvalue = ((metaflags >> 3) & 0x1f)
    return InstructionSetClasses[realvalue]

def _getFC(metaflags):
    realvalue = (metaflags & 0x7)
    try:
        return FlowControlFlags[realvalue]
    except IndexError:
        print "Bad meta-flags: %d", realvalue
        raise

def _getMnem(opcode):
    return Mnemonics.get(opcode, "UNDEFINED")

def _unsignedToSigned64(val):
    return int(val if val < 0x8000000000000000 else (val - 0x10000000000000000))

def _unsignedToSigned32(val):
    return int(val if val < 0x80000000 else (val - 0x10000000))

if SUPPORT_64BIT_OFFSET:
    _unsignedToSigned = _unsignedToSigned64
else:
    _unsignedToSigned = _unsignedToSigned32

class Operand (object):
    def __init__(self, type, *args):
        self.type = type
        self.index = None
        self.name = ""
        self.size = 0
        self.value = 0
        self.disp = 0
        self.dispSize = 0
        self.base = 0
        if type == OPERAND_IMMEDIATE:
            self.value = int(args[0])
            self.size = args[1]
        elif type == OPERAND_REGISTER:
            self.index = args[0]
            self.size = args[1]
            self.name = Registers[self.index]
        elif type == OPERAND_MEMORY:
            self.base = args[0] if args[0] != R_NONE else None
            self.index = args[1]
            self.size = args[2]
            self.scale = args[3] if args[3] > 1 else 1
            self.disp = int(args[4])
            self.dispSize = args[5]
        elif type == OPERAND_ABSOLUTE_ADDRESS:
            self.size = args[0]
            self.disp = int(args[1])
            self.dispSize = args[2]
        elif type == OPERAND_FAR_MEMORY:
            self.size = args[2]
            self.seg = args[0]
            self.off = args[1]

    def _toText(self):
        if self.type == OPERAND_IMMEDIATE:
            if self.value >= 0:
                return "0x%x" % self.value
            else:
                return "-0x%x" % abs(self.value)
        elif self.type == OPERAND_REGISTER:
            return self.name
        elif self.type == OPERAND_ABSOLUTE_ADDRESS:
            return '[0x%x]' % self.disp
        elif self.type == OPERAND_FAR_MEMORY:
            return '%s:%s' % (hex(self.seg), hex(self.off))
        elif (self.type == OPERAND_MEMORY):
            result = "["
            if self.base != None:
                result += Registers[self.base] + "+"
            if self.index != None:
                result += Registers[self.index]
                if self.scale > 1:
                    result += "*%d" % self.scale
            if self.disp >= 0:
                result += "+0x%x" % self.disp
            else:
                result += "-0x%x" % abs(self.disp)
            return result + "]"
    def __str__(self):
        return self._toText()


class Instruction (object):
    def __init__(self, di, instructionBytes, dt):
        "Expects a filled _DInst structure, and the corresponding byte code of the whole instruction"
        #self.di = di
        flags = di.flags
        self.instructionBytes = instructionBytes
        self.opcode = di.opcode
        self.operands = []
        self.flags = []
        self.rawFlags = di.flags
        self.instructionClass = _getISC(0)
        self.flowControl = _getFC(0)
        self.address = di.addr
        self.size = di.size
        self.dt = dt
        self.valid = False
        if di.segment != R_NONE:
            self.segment = di.segment & 0x7f
            self.isSegmentDefault = (di.segment & 0x80) == 0x80
        else:
            self.segment = R_NONE
            self.isSegmentDefault = False
        self.unusedPrefixesMask = di.unusedPrefixesMask

        if flags == FLAG_NOT_DECODABLE:
            self.mnemonic = 'DB 0x%02x' % (di.imm.byte)
            self.flags = ['FLAG_NOT_DECODABLE']
            return

        self.valid = True
        self.mnemonic = _getMnem(self.opcode)

        # decompose the flags for a valid opcode
        for index, flag in enumerate(FLAGS):
            if (flags & (1 << index)) != 0:
                self.flags.append(flag)

        # read the operands
        for operand in di.ops:
            if operand.type != O_NONE:
                self.operands.append(self._extractOperand(di, operand))

        # decode the meta-flags
        metas = di.meta
        self.instructionClass = _getISC(metas)
        self.flowControl = _getFC(metas)

    def _extractOperand(self, di, operand):
        # a single operand can be up to: reg1 + reg2*scale + constant
        if operand.type == O_IMM:
            if ("FLAG_IMM_SIGNED" in self.flags):
                # immediate is sign-extended, do your thing. it's already signed, just make it Python-signed.
                constant = _unsignedToSigned(di.imm.sqword)
            else:
                # immediate is zero-extended, though it's already aligned.
                constant = di.imm.qword
            return Operand(OPERAND_IMMEDIATE, constant, operand.size)
        elif operand.type == O_IMM1: # first operand for ENTER
            return Operand(OPERAND_IMMEDIATE, di.imm.ex.i1, operand.size)
        elif operand.type == O_IMM2: # second operand for ENTER
            return Operand(OPERAND_IMMEDIATE, di.imm.ex.i2, operand.size)
        elif operand.type == O_REG:
            return Operand(OPERAND_REGISTER, operand.index, operand.size)
        elif operand.type == O_MEM:
            return Operand(OPERAND_MEMORY, di.base, operand.index, operand.size, di.scale, _unsignedToSigned(di.disp), di.dispSize)
        elif operand.type == O_SMEM:
            return Operand(OPERAND_MEMORY, None, operand.index, operand.size, di.scale, _unsignedToSigned(di.disp), di.dispSize)
        elif operand.type == O_DISP:
            return Operand(OPERAND_ABSOLUTE_ADDRESS, operand.size, di.disp, di.dispSize)
        elif operand.type == O_PC:
            return Operand(OPERAND_IMMEDIATE, _unsignedToSigned(di.imm.addr) + self.address + self.size, operand.size)
        elif operand.type == O_PTR:
            return Operand(OPERAND_FAR_MEMORY, di.imm.ptr.seg, di.imm.ptr.off, operand.size)
        else:
            raise ValueError("Unknown operand type encountered: %d!" % operand.type)

    def _toText(self):
        # use the decode which already returns the text formatted well (with prefixes, etc).
        return Decode(self.address, self.instructionBytes, self.dt)[0][2]

    def __str__(self):
        return self._toText()


def DecomposeGenerator(codeOffset, code, dt, features = 0):
    """
    @type  codeOffset: long
    @param codeOffset: Memory address where the code is located.
        This is B{not} an offset into the code!
        It's the actual memory address where it was read from.

    @type  code: str
    @param code: Code to disassemble.

    @type  dt: int
    @param dt: Disassembly type. Can be one of the following:

         * L{Decode16Bits}: 80286 decoding

         * L{Decode32Bits}: IA-32 decoding

         * L{Decode64Bits}: AMD64 decoding

    @type  features: int
    @param features: A flow control stopping criterion, eg. DF_STOP_ON_CALL.
                     or other features, eg. DF_RETURN_FC_ONLY.

    @rtype:  generator of TODO
    @return: Generator of TODO

    @raise ValueError: Invalid arguments.
    """

    if not code:
        return

    if not codeOffset:
        codeOffset = 0

    if dt not in (Decode16Bits, Decode32Bits, Decode64Bits):
        raise ValueError("Invalid decode type value: %r" % (dt,))

    codeLen         = len(code)
    code_buf        = create_string_buffer(code)
    p_code          = byref(code_buf)
    result          = (_DInst * MAX_INSTRUCTIONS)()
    instruction_off = 0

    while codeLen > 0:
        
        usedInstructionsCount = c_uint(0)
        codeInfo = _CodeInfo(_OffsetType(codeOffset), _OffsetType(0), cast(p_code, c_char_p), codeLen, dt, features)
        status = internal_decompose(byref(codeInfo), byref(result), MAX_INSTRUCTIONS, byref(usedInstructionsCount))
        if status == DECRES_INPUTERR:
            raise ValueError("Invalid arguments passed to distorm_decode()")

        used = usedInstructionsCount.value
        if not used:
            break

        delta = 0
        for index in xrange(used):
            di = result[index]
            yield Instruction(di, code[instruction_off : instruction_off + di.size], dt)
            delta += di.size
            instruction_off += di.size

        if delta <= 0:
            break
        codeOffset = codeOffset + delta
        p_code     = byref(code_buf, instruction_off)
        codeLen    = codeLen - delta
	if (features & DF_STOP_ON_FLOW_CONTROL) != 0:
		break # User passed a stop flag.

def Decompose(offset, code, type = Decode32Bits, features = 0):
    """
    @type  offset: long
    @param offset: Memory address where the code is located.
        This is B{not} an offset into the code!
        It's the actual memory address where it was read from.

    @type  code: str
    @param code: Code to disassemble.

    @type  type: int
    @param type: Disassembly type. Can be one of the following:

         * L{Decode16Bits}: 80286 decoding

         * L{Decode32Bits}: IA-32 decoding

         * L{Decode64Bits}: AMD64 decoding

    @type  features: int
    @param features: A flow control stopping criterion, eg. DF_STOP_ON_CALL.
                     or other features, eg. DF_RETURN_FC_ONLY.

    @rtype:  TODO
    @return: TODO
    @raise ValueError: Invalid arguments.
    """
    return list(DecomposeGenerator(offset, code, type, features))
