__author__ = 'khoai'

import queue
from queue import Queue

class MatchType:
    TREE = 'Tree'
    FINGER_PRINT = 'Fingerprint'

class MatchStatus:
    MATCH =     'Match'
    MODIFIED =  'Modified'
    REMOVE =    'Remove'

class DiffInfo:
    def __init__(self):
        self.isSet = False
        self.match = 0
        self.matchType = None
        self.matchStatus = None
        self.fingerPrint = ''
        self.parent = None
        self.join = None
        self.traveled = False

def buildFingerPrint(node):
    fingerPrint = ''
    for ins in node.data:
        #print str(ins)
        fingerPrint += ins.instructionBytes.encode("hex")
    return fingerPrint

def levenshtein(word1, word2):
    # source at: http://stevehanov.ca/blog/index.php?id=114
    columns = len(word1) + 1
    rows = len(word2) + 1

    # build first row
    currentRow = [0]
    for column in xrange( 1, columns ):
        currentRow.append( currentRow[column - 1] + 1 )

    for row in xrange( 1, rows ):
        previousRow = currentRow
        currentRow = [ previousRow[0] + 1 ]

        for column in xrange( 1, columns ):

            insertCost = currentRow[column - 1] + 1
            deleteCost = previousRow[column] + 1

            if word1[column - 1] != word2[row - 1]:
                replaceCost = previousRow[ column - 1 ] + 1
            else:
                replaceCost = previousRow[ column - 1 ]

            currentRow.append( min( insertCost, deleteCost, replaceCost ) )
    return currentRow[-1]

def fingerPrintDistance(finger1, finger2):
    diffScore = levenshtein(finger1, finger2)
    return (int) ((100) - diffScore*100/(max(len(finger1), len(finger2))))

def compareNode(node1, node2):
    #info1 = DiffInfo
    fingerPrint1 = buildFingerPrint(node1)
    fingerPrint2 = buildFingerPrint(node2)

    match = fingerPrintDistance(fingerPrint1, fingerPrint2)
    if (match == 100):
        # good fingerprint
        return (MatchType.FINGER_PRINT, match)

def findBrotherNode(node, lsNode):
    for node2 in lsNode:
        if (node2.userData.isSet == False):
            #--- prior for parent relative
            parent2 = node2.userData.parent
            parent1 = node.userData.parent

            if (parent1 != parent2) & ((parent1 == None) | (parent1 == None)):
                continue

            flag = False
            if (parent1 == parent2):
                flag = True
            elif (parent2.userData.join == parent1):
                flag = True

            if flag == True:
                # brother node
                similarMeasure = fingerPrintDistance(node2.userData.fingerPrint, node.userData.fingerPrint)
                if ( similarMeasure > 50):
                    # join node
                    node.userData.isSet = node2.userData.isSet = True
                    node.userData.match = node2.userData.match = similarMeasure
                    node.userData.matchType = node2.userData.matchType = MatchType.TREE
                    node.userData.matchStatus = node2.userData.matchStatus = MatchStatus.MATCH if similarMeasure == 100 else MatchStatus.MODIFIED
                    node.userData.join = node2
                    node2.userData.join = node
                    return node2
    return None

def findSimilarNode(node, lsNode):
    for node2 in lsNode:
        if (node2.userData.isSet == False):
            similarMeasure = fingerPrintDistance(node2.userData.fingerPrint, node.userData.fingerPrint)
            if ( similarMeasure > 80):
                # join node
                node.userData.isSet = node2.userData.isSet = True
                node.userData.match = node2.userData.match = similarMeasure
                node.userData.matchType = node2.userData.matchType = MatchType.FINGER_PRINT
                node.userData.matchStatus = node2.userData.matchStatus = MatchStatus.MATCH if similarMeasure == 100 else MatchStatus.MODIFIED
                node.userData.join = node2
                node2.userData.join = node
                return node2
    return None

def travelDiff(lsNode1, lsNode2):
    for node in lsNode1:
        if findBrotherNode(node, lsNode2) == None:
            if findSimilarNode(node, lsNode2) == None:
                node.userData.isSet = True
                node.userData.match = 0
                node.userData.matchType = MatchType.TREE
                node.userData.matchStatus = MatchStatus.REMOVE
                node.userData.join = None

    #---
    for node in lsNode2:
        if (node.userData.isSet == False):
            node.userData.isSet = True
            node.userData.match = 0
            node.userData.matchType = MatchType.TREE
            node.userData.matchStatus = MatchStatus.REMOVE
            node.userData.join = None

def BFTravelResult(lsBlock):
    for block in lsBlock:
        parentNumber = 0 if block.userData.parent == None else block.userData.parent.name
        print "%x : %x -> %d (%s) - %s" % (block.name, block.userData.join.name, block.userData.match, block.userData.matchType, block.userData.matchStatus)

def BFTravel2list(rootNode):
    queue = Queue()
    queue.push(rootNode)

    lsBlock = []
    while queue.isEmpty() == False:
        node = queue.pop()
        if node.userData == None:
            info = DiffInfo()
            node.userData = info
        node.userData.fingerPrint = buildFingerPrint(node)
        lsBlock.append(node)

        # print ("%x : %s") % (node.name, node.userData.fingerPrint)
        for childOffset in node.children:
            childNode = node.children[childOffset]
            if childNode.userData == None:
                info = DiffInfo()
                info.parent = node
                childNode.userData = info
                queue.push(childNode)

    return lsBlock

def diffGraph(graph1, graph2):
    #--- build fingerprint
    print "--- fingerPrint: graph1"
    lsBlock1 = BFTravel2list(graph1)
    # BFTravelResult(lsBlock1)

    print "--- fingerPrint: graph2"
    lsBlock2 = BFTravel2list(graph2)
    # BFTravelResult(lsBlock2)
    #--- diff two graph
    travelDiff(lsBlock1, lsBlock2)

    BFTravelResult(lsBlock1)

    # return the similar percent of two file

