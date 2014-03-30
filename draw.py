__author__ = 'khoai'

import pydot
import diff
from diff import MatchStatus

class MatchColor:
    MATCH =     '#FFFFFF'
    MODIFIED =  '#F3F781'
    REMOVE =    '#F79F81'

class Draw:
    def __init__(self):
        self.dot = pydot.Dot(graph_type='digraph')
        self.dots = dict()

    def drawCfg(self, rootNode):
        code_line = ""
        # --- avoid loop
        if rootNode.name in self.dots.keys():
            return self.dots[rootNode.name]

        code_line += "loc_%x>\l" % (rootNode.name)
        for ins in rootNode.data:
            #print str(ins)
            code_line += str(ins) + "\l"

        colorCode = MatchColor.MATCH
        if rootNode.userData != None:
            if rootNode.userData.matchStatus == MatchStatus.MODIFIED:
                colorCode = MatchColor.MODIFIED
            elif rootNode.userData.matchStatus == MatchStatus.REMOVE:
                colorCode = MatchColor.REMOVE

        dot_node = pydot.Node(code_line, style="filled", fillcolor=colorCode, shape='rectangle', nojustify=False)
        self.dots[rootNode.name] = dot_node
        #stack.append(rootNode.name)
        self.dot.add_node(dot_node)

        for childOffset in rootNode.children:
            childNode = rootNode.children[childOffset]
            childDot = self.drawCfg(childNode)
            self.dot.add_edge(pydot.Edge(dot_node, childDot))
            #dot.edge(str(hex(rootNode.name)), str(hex(childNode.name)), constraint='True')
        return dot_node

    def save(self, file):
        self.dot.write_png(file)

    def drawAndSave(self, rootNode, file):
        self.drawCfg(rootNode)
        self.save(file)
