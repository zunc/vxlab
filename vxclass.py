__author__ = 'khoai'

import diasm
import draw
import dump
import diff

#--- generate control flow graph
if __name__ == "__main__1":
    file = "for04"
    sample = "/home/khoai/Desktop/research/vxclass/sample/" + file  + ".exe"

    file = diasm.bDiasm(sample)
    asm_code = file.diasm()

    cfg_generator = diasm.ControlFlowGenerator(asm_code)
    #scode = control_flow_generator.buildTextBlock(diasm.ep_ava)
    #print scode

    # 0x4013a0 : offset main function hardcode for test main function
    cfgNode = cfg_generator.buildControlFlow(file.ep_ava)

    dot = draw.Draw()
    dot.drawCfg(cfgNode)
    dot.save("picture/" + file + "_main.png")

    dump.dumpData(cfgNode, "cfg/" + file + ".vx")

if __name__ == "__main__":
    file01 = "for01"
    file04 = "for04"
    # compare two graph
    graph01 = dump.loadData("cfg/" + file01 + "_main.vx")
    graph02 = dump.loadData("cfg/" + file04 + "_main.vx")

    diff.diffGraph(graph01, graph02)
    # diff.BFTravelResult(graph01)

    draw.Draw().drawAndSave(graph01, "picture/" + file01 + "_diff.png")
    draw.Draw().drawAndSave(graph02, "picture/" + file04 + "_diff.png")
    print "DONE"


