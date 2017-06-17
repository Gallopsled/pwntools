import pefile
import os
from pwnlib.log import getLogger
log = getLogger(__name__)
__all__ = ['PE']

class PE(object):
    """Wrapper around pefile.

    Example:

        .. code-block:: python

           >>> calc = PE(which('calc.exe'))
          
    """

    # These class-level intitializers are only for ReadTheDocs
    path = ''
    pe = None
       
   
    def __init__(self, path, checksec=False):
    
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE   = 0x40
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT      = 0x0100
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       = 10
           
        self.address = 0
        self.symbols = {}
        self.path = os.path.abspath(path)
        self.pe = pefile.PE(self.path)
        self.load_addr = self.pe.OPTIONAL_HEADER.BaseOfCode
        
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.dep = None
        self.aslr = None
        self.safeseh = None
        
        if checksec:
            #Check DEP
            self.dep = ( self.pe.OPTIONAL_HEADER.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0
            #Check ASLR
            self.aslr = ( self.pe.OPTIONAL_HEADER.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0
            #Check SafeSEH
            self.safeseh = ( self.pe.DIRECTORY_ENTRY_LOAD_CONFIG != None ) and (self.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size != 0 )
            log.info("DEP: " + str(self.dep) )
            log.info("ASLR: " + str(self.aslr) )
            log.info("SafeSEH: " + str(self.safeseh) )
        
        #Populate symbol dictionary
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                self.symbols[exp.name] = exp.address