from threading import Thread
from Queue import Queue, Empty

class NonBlockingStreamReader:

    def __init__(self, stream):
        '''
        stream: the stream to read from.
        Usually a process' stdout or stderr.
        '''
        self._s = stream
        self._q = Queue()

        def _populateQueue(stream, queue):
            '''
            Collect bytes from 'stream' and put them in 'queue'.
            '''
            while True:
                ret_byte = stream.read(1)
                if ret_byte:
                    #print "Byte: %s\n" % ret_byte
                    queue.put(ret_byte)
                else:
                    break

        self._t = Thread(target = _populateQueue, args = (self._s, self._q))
        self._t.daemon = True
        self._t.start() #start collecting lines from the stream
        
    def canread( self ):
        #Check if the queue is empty
        return not self._q.empty()
            
    def readbyte(self, timeout = None):
    
        if self.canread():
            try:
                return self._q.get(block = timeout is not None, timeout = timeout)
            except Empty:
                return None
        
        return None
        
    def read(self, num=100000 , timeout = None):
        data = ''
        cur_byte = ''
        
        count = 0
        #print "Reading %d bytes" % num
        while cur_byte != None and count < num:
            cur_byte = self.readbyte(timeout)
            if cur_byte:
                #print "Byte: %s" % cur_byte
                data  += cur_byte
                count += 1
                
        return data
         
    def readall(self, timeout = None):
        data = ''
        cur_byte = ''
        
        while cur_byte != None:
            cur_byte = self.readbyte(timeout)
            if cur_byte:
                data += cur_byte
        return data
        