#Add the missing parts of LPDDR2TOP in the memory map for NSKBL
#@author CreepNT
#@category Vita
#@keybinding
#@menupath Vita.Add RAM for NSKBL
#@toolbar

LPDDR2_START = 0x40000000
LPDDR2_END   = 0x60000000
nskbl_start  = 0x51000000

mem = currentProgram.getMemory()

def getAddr(va):
	return currentProgram.parseAddress("0x%08X" % va)[0]

nskbl = mem.getBlock(getAddr(nskbl_start))
if (nskbl == None):
    print("NSKBL not detected at 0x%08X - aborting" % nskbl_start)
elif ((nskbl.getStart().getOffset() == LPDDR2_START) and
        (nskbl.getEnd().add(1).getOffset() == LPDDR2_END)):
    print("LPDDR2TOP is already mapped!")
else:
    #Create a block for the DRAM before NSKBL (0x4000_0000 to nskbl_start)
    block_before = mem.createInitializedBlock(
        "LPDDR0",
        getAddr(LPDDR2_START),
        nskbl_start - LPDDR2_START,
        0, monitor, False
    )

    block_before.setRead(nskbl.isRead())
    block_before.setWrite(nskbl.isWrite())
    block_before.setExecute(nskbl.isExecute())
    block_before.setComment("LPDDR2TOP / DRAM Bank 0")

    #Create a block for the DRAM after NSKBL (up to 0x6000_0000)
    #N.B. we don't need to set details on this block
    #They will get copied from previous block during join
    after_start = nskbl.getEnd().add(1)
    block_after = mem.createInitializedBlock(
        "_", after_start,
        LPDDR2_END - after_start.getOffset(),
        0, monitor, False
    )

    tmp = mem.join(block_before, nskbl)
    tmp = mem.join(tmp, block_after)