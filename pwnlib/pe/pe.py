import pefile
import os

class PE(object):
    """Wrapper around pefile.

    Example:

        .. code-block:: python

           >>> calc = PE(which('calc.exe'))
          
    """

    # These class-level intitializers are only for ReadTheDocs
    path = ''
    pe = None
    
   
    def __init__(self, path, checksec=True):
           
        self.address = 0
        self.path = os.path.abspath(path)
        self.pe = pefile.PE(self.path)
        self.load_addr = self.pe.OPTIONAL_HEADER.BaseOfCode