#!/usr/bin/env python

# This code was borrowed from gDesklets

_DELIMITER = "@@"
_MATCH_ONE = "?"
_MATCH_MANY = "%"


#
# Class for the node of a compressed trie.
#
class _TrieNode(object):

    #__slots__ = ('__body', '__children', '__values')


    def __init__(self):
 
        # the body elements; since the trie is compressed, there may be more
        # than one
        self.__body = []

        # the children of the node
        self.__children = {}

        # the values stored in the node
        self.__values = []


    def _set_body(self, body): self.__body = body[:]
    def _set_children(self, children): self.__children = children.copy()
    def _set_values(self, values): self.__values = values[:]


    #
    # Inserts a new string into the trie.
    #
    def insert(self, data, value):
        
        # if the node is empty, just fill it
        if (not self.__body):
            self._set_body(data)
            self.__values.append(value)
            return

        index = 0
        length = len(self.__body)

        # check how far the elements match
        while (index < length):
            # split up node if elements don't match
            if (data[index] != self.__body[index]):
                ext_node = _TrieNode()
                ext_node._set_body(self.__body[index:])
                ext_node._set_children(self.__children)
                ext_node._set_values(self.__values)

                new_node = _TrieNode()
                new_node.insert(data[index:], value)
                
                self.__children = {self.__body[index]: ext_node,
                                   data[index]: new_node}
                self.__body = self.__body[:index]
                self.__values = []
                return
            #end if
            index += 1
        #end while

        # use this node if the given string exactly matches the body string
        if (index == len(data)):
            self.__values.append(value)
            return

        # insert node
        node = self.__children.get(data[index])
        if (node):
            # insert into existing node
            node.insert(data[index:], value)
        else:
            # create a new node
            new_node = _TrieNode()
            new_node.insert(data[index:], value)
            self.__children[data[index]] = new_node


    #
    # Retrieves the values which are stored for the given string. The string
    # may contain the wildcards ? (match any character) and * (match zero or
    # more characters).
    #
    # FIXME: clean up
    #
    def retrieve(self, data, case_sensitive):

        index = 0
        length = len(self.__body)

        values = []
        while (index < length):
            if (case_sensitive):
                next = data[index]
                char = self.__body[index]
            else:
                next = data[index].lower()
                char = self.__body[index].lower()
            
            if (next == _MATCH_ONE and char != _DELIMITER):
                index += 1
            elif (next == _MATCH_ONE):
                return []
            
            # the MANY wildcard can be translated to ONE wildcards
            elif (next == _MATCH_MANY):
                prefix = data[:index]
                suffix = data[index + 1:]
                values += self.retrieve(prefix + suffix, case_sensitive)
                values += self.retrieve(prefix + [_MATCH_ONE, _MATCH_MANY] +
                                        suffix, case_sensitive)
                return values
            
            elif (next != char):
                return []
            
            else:
                index += 1
        #end while

        if (index >= len(data)): return self.__values

        next = data[index]
        if (next in (_MATCH_ONE, _MATCH_MANY)):
            for node in self.__children.values():
                values += node.retrieve(data[index:], case_sensitive)
            return values
                    
        else:
            node1 = self.__children.get(next)
            if (not case_sensitive): node2 = self.__children.get(next.lower())
            else: node2 = None
            if (not case_sensitive): node3 = self.__children.get(next.upper())
            else: node3 = None

            if (node1 or node2 or node3):
                l1 = []
                l2 = []
                l3 = []
                if (node1):
                    l1 = node1.retrieve(data[index:], case_sensitive)
                if (node2):
                    l2 = node2.retrieve(data[index:], case_sensitive)
                if (node3):
                    l3 = node3.retrieve(data[index:], case_sensitive)

                return values + l1 + l2 + l3
            else:
                return values + self.__values


    #
    # Recursive method for removing entries. If it return True, then the node
    # could be removed successfully, otherwise the node is still in use.
    #
    def remove(self, key, value):

        # recursively check the children, if the key matches
        if (len(key) > len(self.__body) and
               key[:len(self.__body)] == self.__body):
            key = key[len(self.__body):]
            next = key[0]
            child = self.__children.get(next)
            if (child):
                to_remove = child.remove(key, value)
                if (to_remove):
                    del self.__children[next]
                
        # remove the value from this node
        else:
            try:
                self.__values.remove(value)
            except ValueError:
                pass

        # if the node has become empty, then we can remove it
        if (not self.__values and not self.__children):
            return True
        else:
            return False


    def get_size(self):

        size = 1
        for c in self.__children.values():
            size += c.get_size()

        return size



#
# Class for a trie.
#
class Trie:

    #__slots__ = ('__root', '__case_sensitive')

    def __init__(self):

        self.__root = _TrieNode()
        self.__case_sensitive = True

        # table for storing all indices of a value: value -> [indices]
        self.__index_table = {}

    #
    # Sets the case sensitivity for searches in the trie.
    #
    def set_case_sensitive(self, value): self.__case_sensitive = value
    

    #
    # Inserts a value into the trie for the given list of key elements.
    # A list element is usually a letter of a string which is to be indexed.
    #
    def insert(self, key, value):

        key = [_DELIMITER] + key + [_DELIMITER]
        self.__root.insert(key, value)

        if (not value in self.__index_table): self.__index_table[value] = []
        self.__index_table[value].append(key)


    #
    # Retrieves the stored value for the given list of key elements. A list
    # element is usually a letter of an indexed string.
    #
    def retrieve(self, key):
		
        key = [_DELIMITER] + key + [_DELIMITER]
        values = self.__root.retrieve(key, self.__case_sensitive)

        if len(values) <= 1:
            return values

        # remove duplicates
        values.sort()
        new = []
        current = None
        for v in values:
            if (v != current):
                new.append(v)
                current = v
        #end for
        return new


    #
    # Removes the given value from the trie.
    #
    def remove(self, value):

        indices = self.__index_table.get(value, [])
        for index in indices:
            self.__root.remove(index, value)


    def get_size(self):

        return self.__root.get_size()

    #
    # Get key from the given value
    #
    def getkey(self, value):
		
        result = []
        indices = self.__index_table.get(value, [])
        for key in indices:
			result.append(key[1])
        return result


if (__name__ == "__main__"):

    text = """
    This is just a plain text which we are going to index. There are lots of
    words in it, so this will be some kind of stress test for our trie willay
    implementation. Let's see how well this will work with compressed tries.
    """

    import sys
    if '.' not in sys.path: sys.path.append('.')
    if '..' not in sys.path: sys.path.append('..')

    keys = text.split() #open('/usr/share/dict/words').read().split()#[:1000]

    t = Trie()
    for word in keys:
        t.insert(list(word), word)

    for key in keys:
        t.retrieve(list(key))

    a = t.retrieve(list("w?ll*"))
    print a, len(a)

    for word in text.split():
        t.remove(word)
        print t.get_size()

    for word in keys:
        t.insert(list(word), word)
        print t.get_size()

    a = t.retrieve(list("t*"))
    print a, len(a)

