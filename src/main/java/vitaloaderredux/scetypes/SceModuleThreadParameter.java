package vitaloaderredux.scetypes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.loader.ArmElfPrxLoaderContext;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;

public class SceModuleThreadParameter {

	static public final int SIZE = 0x14;
	static public final String STRUCTURE_NAME = "SceModuleThreadParameter";
	static public final int NUM_PARAMS_FOR_VITA = 4;

	public final int numParams;
	public final int initPriority;
	public final int stackSize;
	public final int attr;
	public final int cpuAffinityMask;

	private final String entrypointName;

	public SceModuleThreadParameter(BinaryReader reader, String mtpEntrypointName) throws IOException {
		numParams = reader.readNextInt();
		if (numParams != NUM_PARAMS_FOR_VITA) {
			throw new MalformedElfException(String.format("Invalid numParams=%d (!= %d) in SceModuleThreadParameter", numParams, NUM_PARAMS_FOR_VITA));
		}

		initPriority = reader.readNextInt();
		stackSize = reader.readNextInt();
		attr = reader.readNextInt();
		cpuAffinityMask = reader.readNextInt();

		Utils.assertBRSize(mtpEntrypointName, reader, SIZE);

		entrypointName = mtpEntrypointName;
	}

	private StructureDataType DATATYPE = null;
	public DataType toDataType() {
		if (DATATYPE == null) {
			DATATYPE = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
			DATATYPE.add(Datatypes.u32, "numParams", "Number of parameters in this structure (4)");
			DATATYPE.add(Datatypes.s32, "initPriority", "Initial priority of the entrypoint thread");
			DATATYPE.add(Datatypes.u32, "stackSize", "Size of the entrypoint thread's stack (in bytes)");
			DATATYPE.add(Datatypes.u32, "attr", "Thread attributes (unused on Vita)");
			DATATYPE.add(Datatypes.s32, "cpuAffinityMask", "Affinity mask of the entrypoint thread");

			Utils.assertStructureSize(DATATYPE, SIZE);
		}
		return DATATYPE;
	}

	public void process(ArmElfPrxLoaderContext ctx, Address mtpAddress) throws Exception {
		ctx.createLabeledDataInNamespace(mtpAddress, ctx.moduleNamespace, "sce_" + entrypointName + "_thread_parameter", toDataType());
	}

	public void addCommentToEntrypoint(ArmElfPrxLoaderContext ctx, int entrypointVA) throws Exception {
		final int priority = (initPriority == 0) ? 0x10000100 : initPriority;
		final int stackSz = (stackSize == 0) ? (256*1024) : stackSize;
		final int affinityMask = (cpuAffinityMask == 0) ? 0xF : cpuAffinityMask;

		String comment = entrypointName + " thread parameters:\n";
		comment += "Initial priority: " + Utils.prettifyPriority(priority) + "\n";
		comment += "Stack size: " + Utils.prettifySize(stackSz) + "\n";
		comment += "CPU affinity mask: " + Utils.prettifyCpuAffinityMask(affinityMask);

		Address epAddr = ctx.getAddressInDefaultAS(entrypointVA & ~1);
		Function epFunc = ctx.funcMgr.getFunctionAt(epAddr);

		String oldComment = epFunc.getComment();
		if (oldComment != null) {
			comment = oldComment + "\n\n" + comment;
		}
		epFunc.setComment(comment);
	}
}
