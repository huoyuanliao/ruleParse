#!/usr/bin/env python

class Signature(object):
    def __init__(self,line):
        self.id  = Signature._getsid_(line)
        self.version = Signature._getversion_(line)
        self.rule = line

    @staticmethod
    def _isvalid_(line):
        if len(line) >= 5 and line[0:5] == 'alert':
            return True
        return False

    @staticmethod
    def _getsid_(line):
        sid = -1
        if Signature._isvalid_(line):
            idx = line.find("; sid:")
            if idx != -1:
                sid = line[idx+6: idx+13]
        return sid

    @staticmethod
    def _getversion_(line):
        return 0 

class RuleFile(object):
    def __init__(self,filePath):
        self.fileName = filePath
        self.signatures = RuleFile._parse_(filePath)

    @staticmethod
    def _parse_(filePath):
        with open(filePath) as f:
            signature = []
            for line in f.readlines():
                sig = Signature(line)
                if sig.id == -1:
                    continue
                signature.append(sig)
            return signature

def ruleParseTest(rulePath):
    rulefile = RuleFile(rulePath)
    print rulefile.fileName
    for sig in rulefile.signatures:
        print sig.id
def main():
    ruleParseTest('test.rules')

if __name__ == '__main__':
    main()
