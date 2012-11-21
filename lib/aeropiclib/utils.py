

def getarch():
    """
    Get architecture of debugged program
    
    Returns:
    - tuple of architecture info (arch (String), bits (Int))
    """
    arch = "unknown"
    bits = 32
    out = self.execute_redirect('maintenance info sections ?').splitlines()
    for line in out:
        if "file type" in line:
            arch = line.split()[-1][:-1]
            break
    if "64" in arch:
        bits = 64
    return (arch, bits)
