#Add memory blocks corresponding to hardware devices to the memory map
#@author CreepNT
#@category Vita
#@keybinding
#@menupath Vita.Add hardware devices
#@toolbar

from ghidra.program.model.mem import MemoryConflictException

mem = currentProgram.getMemory()

num_blocks = 0
num_created = 0
num_conflicts = 0
num_errors = 0

def getAddr(va):
    return currentProgram.parseAddress("0x%08X" % va)[0]

def mapDev(name, base, size=0x1000, comment=""):
    global num_blocks
    global num_created
    global num_conflicts
    global num_errors
    num_blocks += 1

    try:
        blk = mem.createUninitializedBlock(name, getAddr(base), size, False)
        blk.setRead(True)
        blk.setWrite(True)
        blk.setExecute(False)
        blk.setVolatile(True)
        blk.setComment(comment)
        num_created += 1
        return blk
    except MemoryConflictException:
        existing = mem.getBlock(getAddr(base))
        if ((existing == None) or
            (existing.getStart().getOffset() != base) or
            (existing.getSize() != size)):
            print("Conflict creating block %s @ 0x%08X" % (name, base))
            num_conflicts += 1
        else:
            print("Skipped creating block %s - already exists" % name)
        return None
    except:
        print("Failed creating block %s @ 0x%08X" % (name, base))
        num_errors += 1
        return None

mapDev("PERIPHBASE", 0x1A000000, 0x3000)

mapDev("Spad32K", 0x1F000000, 0x8000)

mapDev("SceGpio0Reg", 0xE20A0000, 0x10000)
mapDev("SceGpio1Reg", 0xE0100000, 0x10000)

mapDev("ScePervasiveMisc", 	0xE3100000)
mapDev("ScePervasiveResetReg", 0xE3101000)
mapDev("ScePervasiveGate", 	0xE3102000)
mapDev("ScePervasiveBaseClk", 0xE3103000)
mapDev("SceUartClkgenReg", 	0xE3104000)
mapDev("ScePervasiveVid", 	0xE3105000)
mapDev("ScePervasiveMailboxReg", 0xE3106000)
mapDev("ScePervasiveTas0", 0xE3108000)
mapDev("ScePervasiveTas1", 0xE3109000)
mapDev("ScePervasiveTas2", 0xE310A000)
mapDev("ScePervasiveTas3", 0xE310B000)
mapDev("ScePervasiveTas4", 0xE310C000)
mapDev("ScePervasiveTas5", 0xE310D000)
mapDev("ScePervasiveTas6", 0xE310E000)
mapDev("ScePervasiveTas7", 0xE310F000)
mapDev("ScePervasive2Reg", 0xE3110000)

mapDev("SceTpiuReg", 0xE3203000)
mapDev("SceFunnelReg", 0xE3204000)
mapDev("SceItmReg", 0xE3205000)

mapDev("Base Debug ROM Table", 0xE3200000)
mapDev("ARM Cortex-A9 Debug ROM Table", 0xE3300000)
mapDev("SceDbg0Reg", 0xE3310000)
mapDev("ScePmu0Reg", 0xE3311000)
mapDev("SceDbg1Reg", 0xE3312000)
mapDev("ScePmu1Reg", 0xE3313000)
mapDev("SceDbg2Reg", 0xE3314000)
mapDev("ScePmu2Reg", 0xE3315000)
mapDev("SceDbg3Reg", 0xE3316000)
mapDev("ScePmu3Reg", 0xE3317000)
mapDev("ScePfmReg",  0xE50D0000, 0x2000, "Performance Monitoring/Analysis")

mapDev("SceCti0Reg", 0xE3318000)
mapDev("SceCti1Reg", 0xE3319000)
mapDev("SceCti2Reg", 0xE331A000)
mapDev("SceCti3Reg", 0xE331B000)
#TODO ScePtm
#TODO VFP registers
#TODO Usb/UDCD

mapDev("ARM/CMeP Comm", 0xE0000000, 0x10000)
mapDev("CMeP Reset",    0xE0010000, 0x10000)
mapDev("CMeP 0xE0020000 unknown",        0xE0020000, 0x10000)
mapDev("CMeP Keyring Controller", 0xE0030000, 0x10000)
mapDev("CMeP Math Processor",     0xE0040000, 0x10000)
mapDev("Bigmac Engine", 	    0xE0050000)
mapDev("CMeP Keyring",  0xE0058000, 0x10000)
mapDev("SceEmmcController",       0xE0070000, 0x50000)
mapDev("Unknown CMeP registers",  0xE00C0000, 0x40000)

mapDev("SceSblDMAC5DmacKR", 0xE04E0000, 0x1000, "DMAC5 Key Ring")
mapDev("SceDmacmgrDmac0Reg", 0xE3000000)
mapDev("SceDmacmgrDmac1Reg", 0xE3010000)
mapDev("SceDmacmgrDmac2Reg", 0xE5000000)
mapDev("SceDmacmgrDmac3Reg", 0xE5010000)
mapDev("SceDmacmgrDmac4Reg", 0xE0400000)
mapDev("SceDmacmgrDmac5Reg", 0xE0410000)
mapDev("SceDmacmgrDmac6Reg", 0xE50C0000)

mapDev("SceIftu0RegA", 0xE5020000)
mapDev("SceIftu0RegB", 0xE5021000)
mapDev("SceIftuc0Reg", 0xE5022000)
mapDev("SceIftu1RegA", 0xE5030000)
mapDev("SceIftu1RegB", 0xE5031000)
mapDev("SceItfuc1Reg", 0xE5032000)
mapDev("SceIftu2Reg",  0xE5040000)

mapDev("SceDsi0Reg", 0xE5050000)
mapDev("SceDsi1Reg", 0xE5060000)

mapDev("SceCompatMailbox", 0xE5070000)
mapDev("SceCompatLCDDMA", 0xE5071000)
mapDev("SceCompatSharedSram", 0xE8100000)

mapDev("SceSonyRegbus", 0xE8000000, 0x2000)
mapDev("SceEmcTop", 0xE8200000)
mapDev("SceGrab", 0xE8300000, 0x2000)

mapDev("LPDDR2 I/F CH1", 0xE5880000, 0x10000)
mapDev("LPDDR2 I/F CH0", 0xE6000000, 0x10000)

mapDev("SceSpi0Reg", 0xE0A00000)
mapDev("SceSpi1Reg", 0xE0A10000)
mapDev("SceSpi2Reg", 0xE0A20000)

mapDev("SceLT0", 0xE20B1000)
mapDev("SceLT1", 0xE20B2000)
mapDev("SceLT2", 0xE20B3000)
mapDev("SceLT3", 0xE20B4000)
mapDev("SceLT4", 0xE20B5000)
mapDev("SceLT5", 0xE20B6000)
mapDev("SceWT0", 0xE20B7000)
mapDev("SceWT1", 0xE20B8000)
mapDev("SceWT2", 0xE20B9000)
mapDev("SceWT3", 0xE20BA000)
mapDev("SceWT4", 0xE20BB000)
mapDev("SceWT5", 0xE20BC000)
mapDev("SceWT6", 0xE20BD000)
mapDev("SceWT7", 0xE20BE000)
mapDev("Timer Misc Reg", 0xE20BF000)

mapDev("SceSdio0", 0xE5800000, 0x10000)
mapDev("SceSdio1", 0xE5810000, 0x10000)

mapDev("BUS REGISTERS", 0xEC000000, 0x4000000)

print("%d memory blocks declared" % num_blocks)
print("\t- %d blocks created" % num_created)
print("\t- %d conflicts" % num_conflicts)
print("\t- %d errors" % num_errors)
