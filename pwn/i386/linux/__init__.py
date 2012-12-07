from pwn.internal.shellcraft import *
from .. import *

# Codes
load(['sh',
      'fakesh',
      'setreuidsh',
      'dup',
      'dupsh',
      'listen',
      'connect',
      'connectback',
      'bindshell',
      'findpeer',
      'findpeersh',
      'findtag',
      'findtagsh',
      'acceptloop',
      'setperms',
      'mprotect_all',
      'stackhunter',
      'stackhunter',
#      'stackhunter_helper',
      'fork',
      'echo',
      'cat',
      'readfile'])
