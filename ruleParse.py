#!/usr/bin/env python

import os
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


def _getFileList_(dirPath):
    if os.path.isdir(dirPath):
        fileList = [ftuple[0]+r'/'+filename for ftuple in os.walk(dirPath) for filename in ftuple[2] if filename.endswith('rules')]
    elif os.path.isfile(dirPath):
        fileList = [dirPath]
    else: fileList = []
    return fileList

def parseRuleDir(ruleDir):
    fileList = getFileList(ruleDir)
    ruleObjList = []
    for fname in fileList:
        ruleObjList.append(RuleFile(fname))
    return ruleObjList

def ruleParseTest(rulePath):
    rulefile = RuleFile(rulePath)
    print rulefile.fileName
    for sig in rulefile.signatures:
        print sig.id
def main():
    ruleParseTest('test.rules')

if __name__ == '__main__':
    main()
