TYPE_UNICODE     = 1
TYPE_KEYSYM      = 2
TYPE_FUNCTION    = 3
TYPE_POSITION    = 4
TYPE_EOF         = 5
TYPE_UNKNOWN     = 6
TYPE_UNKNOWN_CSI = 7

# Must be these exact values for CSI parsing to work
MOD_NONE  = 0
MOD_SHIFT = 1 << 0
MOD_ALT   = 1 << 1
MOD_CTRL  = 1 << 2

# Special names in C0
KEY_BACKSPACE    = 1
KEY_TAB          = 2
KEY_ENTER        = 3
KEY_ESCAPE       = 4

# Special names in G0
KEY_SPACE        = 5
KEY_DEL          = 6

# Special keys
KEY_UP           = 7
KEY_DOWN         = 8
KEY_LEFT         = 9
KEY_RIGHT        = 10
KEY_BEGIN        = 11
KEY_FIND         = 12
KEY_INSERT       = 13
KEY_DELETE       = 14
KEY_SELECT       = 15
KEY_PAGEUP       = 16
KEY_PAGEDOWN     = 17
KEY_HOME         = 18
KEY_END          = 19

# Special keys from terminfo
KEY_CANCEL       = 20
KEY_CLEAR        = 21
KEY_CLOSE        = 22
KEY_COMMAND      = 23
KEY_COPY         = 24
KEY_EXIT         = 25
KEY_HELP         = 26
KEY_MARK         = 27
KEY_MESSAGE      = 28
KEY_MOVE         = 29
KEY_OPEN         = 30
KEY_OPTIONS      = 31
KEY_PRINT        = 32
KEY_REDO         = 33
KEY_REFERENCE    = 34
KEY_REFRESH      = 35
KEY_REPLACE      = 36
KEY_RESTART      = 37
KEY_RESUME       = 38
KEY_SAVE         = 39
KEY_SUSPEND      = 40
KEY_UNDO         = 41

# Numeric keypad special keys
KEY_KP0          = 42
KEY_KP1          = 43
KEY_KP2          = 44
KEY_KP3          = 45
KEY_KP4          = 46
KEY_KP5          = 47
KEY_KP6          = 48
KEY_KP7          = 49
KEY_KP8          = 50
KEY_KP9          = 51
KEY_KPENTER      = 52
KEY_KPPLUS       = 53
KEY_KPMINUS      = 54
KEY_KPMULT       = 55
KEY_KPDIV        = 56
KEY_KPCOMMA      = 57
KEY_KPPERIOD     = 58
KEY_KPEQUALS     = 59

# Name mapping
KEY_NAMES = {
    KEY_BACKSPACE : '<backspace>',
    KEY_TAB       : '<tab>',
    KEY_ENTER     : '<enter>',
    KEY_ESCAPE    : '<escape>',
    KEY_SPACE     : '<space>',
    KEY_DEL       : '<del>',
    KEY_UP        : '<up>',
    KEY_DOWN      : '<down>',
    KEY_LEFT      : '<left>',
    KEY_RIGHT     : '<right>',
    KEY_BEGIN     : '<begin>',
    KEY_FIND      : '<find>',
    KEY_INSERT    : '<insert>',
    KEY_DELETE    : '<delete>',
    KEY_SELECT    : '<select>',
    KEY_PAGEUP    : '<page up>',
    KEY_PAGEDOWN  : '<page down>',
    KEY_HOME      : '<home>',
    KEY_END       : '<end>',
    KEY_CANCEL    : '<cancel>',
    KEY_CLEAR     : '<clear>',
    KEY_CLOSE     : '<close>',
    KEY_COMMAND   : '<command>',
    KEY_COPY      : '<copy>',
    KEY_EXIT      : '<exit>',
    KEY_HELP      : '<help>',
    KEY_MARK      : '<mark>',
    KEY_MESSAGE   : '<message>',
    KEY_MOVE      : '<move>',
    KEY_OPEN      : '<open>',
    KEY_OPTIONS   : '<options>',
    KEY_PRINT     : '<print>',
    KEY_REDO      : '<redo>',
    KEY_REFERENCE : '<reference>',
    KEY_REFRESH   : '<refresh>',
    KEY_REPLACE   : '<replace>',
    KEY_RESTART   : '<restart>',
    KEY_RESUME    : '<resume>',
    KEY_SAVE      : '<save>',
    KEY_SUSPEND   : '<suspend>',
    KEY_UNDO      : '<undo>',
    KEY_KP0       : '<kp0>',
    KEY_KP1       : '<kp1>',
    KEY_KP2       : '<kp2>',
    KEY_KP3       : '<kp3>',
    KEY_KP4       : '<kp4>',
    KEY_KP5       : '<kp5>',
    KEY_KP6       : '<kp6>',
    KEY_KP7       : '<kp7>',
    KEY_KP8       : '<kp8>',
    KEY_KP9       : '<kp9>',
    KEY_KPENTER   : '<kp enter>',
    KEY_KPPLUS    : '<kp plus>',
    KEY_KPMINUS   : '<kp minus>',
    KEY_KPMULT    : '<kp mult>',
    KEY_KPDIV     : '<kp div>',
    KEY_KPCOMMA   : '<kp comma>',
    KEY_KPPERIOD  : '<kp period>',
    KEY_KPEQUALS  : '<kp equals>',
    }

KEY_NAMES_REVERSE = {v:k for k, v in KEY_NAMES.items()}

# terminfo

STRNAMES = [
    'ka1',
    'ka3',
    'kb2',
    'kbs',
    'kbeg',
    'kcbt',
    'kc1',
    'kc3',
    'kcan',
    'ktbc',
    'kclr',
    'kclo',
    'kcmd',
    'kcpy',
    'kcrt',
    'kctab',
    'kdch1',
    'kdl1',
    'kcud1',
    'krmir',
    'kend',
    'kent',
    'kel',
    'ked',
    'kext',
    'kf0',
    'kf1',
    'kf10',
    'kf11',
    'kf12',
    'kf13',
    'kf14',
    'kf15',
    'kf16',
    'kf17',
    'kf18',
    'kf19',
    'kf2',
    'kf20',
    'kf21',
    'kf22',
    'kf23',
    'kf24',
    'kf25',
    'kf26',
    'kf27',
    'kf28',
    'kf29',
    'kf3',
    'kf30',
    'kf31',
    'kf32',
    'kf33',
    'kf34',
    'kf35',
    'kf36',
    'kf37',
    'kf38',
    'kf39',
    'kf4',
    'kf40',
    'kf41',
    'kf42',
    'kf43',
    'kf44',
    'kf45',
    'kf46',
    'kf47',
    'kf48',
    'kf49',
    'kf5',
    'kf50',
    'kf51',
    'kf52',
    'kf53',
    'kf54',
    'kf55',
    'kf56',
    'kf57',
    'kf58',
    'kf59',
    'kf6',
    'kf60',
    'kf61',
    'kf62',
    'kf63',
    'kf7',
    'kf8',
    'kf9',
    'kfnd',
    'khlp',
    'khome',
    'kich1',
    'kil1',
    'kcub1',
    'kll',
    'kmrk',
    'kmsg',
    'kmov',
    'knxt',
    'knp',
    'kopn',
    'kopt',
    'kpp',
    'kprv',
    'kprt',
    'krdo',
    'kref',
    'krfr',
    'krpl',
    'krst',
    'kres',
    'kcuf1',
    'ksav',
    'kBEG',
    'kCAN',
    'kCMD',
    'kCPY',
    'kCRT',
    'kDC',
    'kDL',
    'kslt',
    'kEND',
    'kEOL',
    'kEXT',
    'kind',
    'kFND',
    'kHLP',
    'kHOM',
    'kIC',
    'kLFT',
    'kMSG',
    'kMOV',
    'kNXT',
    'kOPT',
    'kPRV',
    'kPRT',
    'kri',
    'kRDO',
    'kRPL',
    'kRIT',
    'kRES',
    'kSAV',
    'kSPD',
    'khts',
    'kUND',
    'kspd',
    'kund',
    'kcuu1',
    ]

STRFNAMES = [
    'a1',
    'a3',
    'b2',
    'backspace',
    'beg',
    'btab',
    'c1',
    'c3',
    'cancel',
    'catab',
    'clear',
    'close',
    'command',
    'copy',
    'create',
    'ctab',
    'dc',
    'dl',
    'down',
    'eic',
    'end',
    'enter',
    'eol',
    'eos',
    'exit',
    'f0',
    'f1',
    'f10',
    'f11',
    'f12',
    'f13',
    'f14',
    'f15',
    'f16',
    'f17',
    'f18',
    'f19',
    'f2',
    'f20',
    'f21',
    'f22',
    'f23',
    'f24',
    'f25',
    'f26',
    'f27',
    'f28',
    'f29',
    'f3',
    'f30',
    'f31',
    'f32',
    'f33',
    'f34',
    'f35',
    'f36',
    'f37',
    'f38',
    'f39',
    'f4',
    'f40',
    'f41',
    'f42',
    'f43',
    'f44',
    'f45',
    'f46',
    'f47',
    'f48',
    'f49',
    'f5',
    'f50',
    'f51',
    'f52',
    'f53',
    'f54',
    'f55',
    'f56',
    'f57',
    'f58',
    'f59',
    'f6',
    'f60',
    'f61',
    'f62',
    'f63',
    'f7',
    'f8',
    'f9',
    'find',
    'help',
    'home',
    'ic',
    'il',
    'left',
    'll',
    'mark',
    'message',
    'move',
    'next',
    'npage',
    'open',
    'options',
    'ppage',
    'previous',
    'print',
    'redo',
    'reference',
    'refresh',
    'replace',
    'restart',
    'resume',
    'right',
    'save',
    'sbeg',
    'scancel',
    'scommand',
    'scopy',
    'screate',
    'sdc',
    'sdl',
    'select',
    'send',
    'seol',
    'sexit',
    'sf',
    'sfind',
    'shelp',
    'shome',
    'sic',
    'sleft',
    'smessage',
    'smove',
    'snext',
    'soptions',
    'sprevious',
    'sprint',
    'sr',
    'sredo',
    'sreplace',
    'sright',
    'srsume',
    'ssave',
    'ssuspend',
    'stab',
    'sundo',
    'suspend',
    'undo',
    'up',
    ]

FUNCSYMS = {
    'backspace' : (KEY_DEL,       MOD_NONE ),
    'begin'     : (KEY_BEGIN,     MOD_NONE ),
    'beg'       : (KEY_BEGIN,     MOD_NONE ),
    'btab'      : (KEY_TAB,       MOD_SHIFT),
    'cancel'    : (KEY_CANCEL,    MOD_NONE ),
    'clear'     : (KEY_CLEAR,     MOD_NONE ),
    'close'     : (KEY_CLOSE,     MOD_NONE ),
    'command'   : (KEY_COMMAND,   MOD_NONE ),
    'copy'      : (KEY_COPY,      MOD_NONE ),
    'dc'        : (KEY_DELETE,    MOD_NONE ),
    'down'      : (KEY_DOWN,      MOD_NONE ),
    'end'       : (KEY_END,       MOD_NONE ),
    'enter'     : (KEY_ENTER,     MOD_NONE ),
    'exit'      : (KEY_EXIT,      MOD_NONE ),
    'find'      : (KEY_FIND,      MOD_NONE ),
    'help'      : (KEY_HELP,      MOD_NONE ),
    'home'      : (KEY_HOME,      MOD_NONE ),
    'ic'        : (KEY_INSERT,    MOD_NONE ),
    'left'      : (KEY_LEFT,      MOD_NONE ),
    'mark'      : (KEY_MARK,      MOD_NONE ),
    'message'   : (KEY_MESSAGE,   MOD_NONE ),
    'move'      : (KEY_MOVE,      MOD_NONE ),
    'next'      : (KEY_PAGEDOWN,  MOD_NONE ), # Not quite, but it's the best we can do
    'npage'     : (KEY_PAGEDOWN,  MOD_NONE ),
    'open'      : (KEY_OPEN,      MOD_NONE ),
    'options'   : (KEY_OPTIONS,   MOD_NONE ),
    'ppage'     : (KEY_PAGEUP,    MOD_NONE ),
    'previous'  : (KEY_PAGEUP,    MOD_NONE ), # Not quite, but it's the best we can do
    'print'     : (KEY_PRINT,     MOD_NONE ),
    'redo'      : (KEY_REDO,      MOD_NONE ),
    'reference' : (KEY_REFERENCE, MOD_NONE ),
    'refresh'   : (KEY_REFRESH,   MOD_NONE ),
    'replace'   : (KEY_REPLACE,   MOD_NONE ),
    'restart'   : (KEY_RESTART,   MOD_NONE ),
    'resume'    : (KEY_RESUME,    MOD_NONE ),
    'right'     : (KEY_RIGHT,     MOD_NONE ),
    'save'      : (KEY_SAVE,      MOD_NONE ),
    'select'    : (KEY_SELECT,    MOD_NONE ),
    'suspend'   : (KEY_SUSPEND,   MOD_NONE ),
    'undo'      : (KEY_UNDO,      MOD_NONE ),
    'up'        : (KEY_UP,        MOD_NONE ),
    }
