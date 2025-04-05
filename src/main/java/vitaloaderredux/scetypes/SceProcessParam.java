package vitaloaderredux.scetypes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.loader.ArmElfPrxLoaderContext;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;
import vitaloaderredux.scetypes.libc.SceLibcParam_0x38;

public class SceProcessParam {

	public static final String STRUCTURE_NAME = "SceProcessParam";
	public static final int MAGIC = 0x32505350; //'PSP2' in little-endian
	public static final int minimal_size = 0x28;

	//TODO: apparently, 0.895 has size 0x20...
	private static final int MIN_SIZE_FOR_AFFINITY_MASK = 0x2C;
	private static final int MIN_SIZE_FOR_LIBC_PARAM = 0x30;
	private static final int MIN_SIZE_FOR_UNK30 = 0x34;
	public static final int maximal_size = 0x34;

	public final int size;
	public final int magic;
	public final int version;
	public final int sdkVersion;
	public final int pSceUserMainThreadName;
	public final int pSceUserMainThreadPriority;
	public final int pSceUserMainThreadStackSize;
	public final int pSceUserMainThreadAttribute;
	public final int pSceProcessName;
	public final int pSceKernelPreloadModuleInhibit;


	public int pSceUserMainThreadCpuAffinityMask = 0;
	public int pLibcParam = 0; //Not present in 0.93x
	public int unk30 = 0;	   //Not present in 0.94x

	public SceProcessParam(BinaryReader reader) throws IOException {
		size = reader.readNextInt();
		if (size < minimal_size || size > maximal_size) {
			throw new MalformedElfException(String.format("Invalid SceProcessParam size 0x%X", size));
		}

		magic = reader.readNextInt();
		if (magic != MAGIC) {
			throw new MalformedElfException(String.format("Invalid SceProcessParam magic 0x%X != 0x%X", magic, MAGIC));
		}

		version = reader.readNextInt();
		sdkVersion = reader.readNextInt();
		pSceUserMainThreadName = reader.readNextInt();
		pSceUserMainThreadPriority = reader.readNextInt();
		pSceUserMainThreadStackSize = reader.readNextInt();
		pSceUserMainThreadAttribute = reader.readNextInt();
		pSceProcessName = reader.readNextInt();
		pSceKernelPreloadModuleInhibit = reader.readNextInt();

		if (size >= MIN_SIZE_FOR_AFFINITY_MASK) {
			pSceUserMainThreadCpuAffinityMask = reader.readNextInt();
		}
		if (size >= MIN_SIZE_FOR_LIBC_PARAM) {
			pLibcParam = reader.readNextInt();
		}
		if (size >= MIN_SIZE_FOR_UNK30) {
			unk30 = reader.readNextInt();
		}

		Utils.assertBRSize(STRUCTURE_NAME, reader, size);
	}

	private StructureDataType DATATYPE = null;
	public DataType toDataType() {
		if (DATATYPE == null) {
			DataType s32ptr = new Pointer32DataType(Datatypes.s32);

			DATATYPE = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
			DATATYPE.add(Datatypes.u32, "size", "Size of this structure");
			DATATYPE.add(Datatypes.makeArray(Datatypes.char8, 4), "magic", "Structure magic ('PSP2')");
			DATATYPE.add(Datatypes.u32, "version", "Structure version");
			DATATYPE.add(Datatypes.u32, "sdkVersion", "Version of the SDK used to build this application");
			DATATYPE.add(Datatypes.stringptr, "pUserMainThreadName", "Pointer to main thread name");
			DATATYPE.add(s32ptr, "pUserMainThreadPriority", "Pointer to main thread priority");
			DATATYPE.add(Datatypes.u32ptr, "pUserMainThreadStackSize", "Pointer to main thread stack size");
			DATATYPE.add(Datatypes.u32ptr, "pUserMainThreadAttribute", "Pointer to main thread attributes");
			DATATYPE.add(Datatypes.stringptr, "pProcessName", "Pointer to process name");
			DATATYPE.add(Datatypes.u32ptr, "pKernelPreloadModuleInhibit", "Pointer to module preload inibition variable");
			if (size >= MIN_SIZE_FOR_AFFINITY_MASK) {
				DATATYPE.add(s32ptr, "pUserMainThreadCpuAffinityMask", "Pointer to main thread CPU affinity mask");
			}
			if (size >= MIN_SIZE_FOR_LIBC_PARAM) {
				//Don't use pointer to SceLibcParam type because structure has multiple variants
				DATATYPE.add(Datatypes.ptr, "pLibcParam", "Pointer to SceLibc parameters");
			}
			if (size >= MIN_SIZE_FOR_UNK30) {
				DATATYPE.add(Datatypes.u32, "unk30", null);
			}

			Utils.assertStructureSize(DATATYPE, size);
		}
		return DATATYPE;
	}

	private void processLibcParam(ArmElfPrxLoaderContext ctx) throws Exception {
		if (size < MIN_SIZE_FOR_LIBC_PARAM)
			return;

		if (pLibcParam == 0) {
			ctx.logger.appendMsg("No SceLibcParam found in SceProcessParam.");
			return;
		}

		Address paramAddr = ctx.getAddressInDefaultAS(pLibcParam);
		BinaryReader reader = ctx.getBinaryReader(paramAddr);


		DataType paramDt = null;
		final int libcParamSize = reader.peekNextInt();
		switch(libcParamSize) {
		case SceLibcParam_0x38.SIZE: {
			SceLibcParam_0x38 libcParam = new SceLibcParam_0x38(reader);
			paramDt = libcParam.toDataType();
			libcParam.process(ctx);
			break;
		}

		case 0x28:
			ctx.logf("Skipped SceLibcParam with size 0x%X (structure not reversed yet)", libcParamSize);

		default:
			ctx.logf("Parsing of SceLibcParam with unsupported size 0x%X skipped", libcParamSize);
			return;
		}

		ctx.createLabeledDataInNamespace(paramAddr, ctx.moduleNamespace, "__sce_libcparam", paramDt);

	}

	public void process(ArmElfPrxLoaderContext ctx, Address processParamAddress) throws Exception {
		ctx.createLabeledDataInNamespace(processParamAddress, ctx.moduleNamespace, "__sce_process_param", toDataType());

		ctx.markupString(pSceUserMainThreadName, "sceUserMainThreadName");
		Data priority = ctx.markupU32(pSceUserMainThreadPriority, "sceUserMainThreadPriority");
		Data stackSize = ctx.markupU32(pSceUserMainThreadStackSize, "sceUserMainThreadStackSize");
		ctx.markupS32(pSceUserMainThreadAttribute, "sceUserMainThreadAttribute");
		ctx.markupString(pSceProcessName, "sceProcessName");
		Data inhibit = ctx.markupU32(pSceKernelPreloadModuleInhibit, "sceKernelPreloadModuleInhibit");
		ctx.markupS32(pSceUserMainThreadCpuAffinityMask, "sceUserMainThreadCpuAffinityMask");

		if (priority != null) {
			priority.setComment(CodeUnit.PLATE_COMMENT, Utils.prettifyPriority(priority.getInt(0)));
		}

		if (stackSize != null) {
			stackSize.setComment(CodeUnit.PLATE_COMMENT, Utils.prettifySize(stackSize.getInt(0)));
		}

		if (inhibit != null) {
			inhibit.setComment(CodeUnit.PLATE_COMMENT, Utils.prettifyInhibitBitflag(inhibit.getInt(0)));
		}

		processLibcParam(ctx);
	}
}
