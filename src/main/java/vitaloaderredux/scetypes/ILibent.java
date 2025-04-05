package vitaloaderredux.scetypes;

import java.nio.IntBuffer;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.loader.ArmElfPrxLoaderContext;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;
import vitaloaderredux.misc.sdt_probedesc_t;

public abstract class ILibent {
	// Library NID returned when it cannot be obtained.
	// In theory, a library could have this value as its NID,
	// however the chances of this happening as so small this
	// that this will Probably Never� cause any problem.
	public static final int UNKNOWN_NID = 0xFFFFFFFF;

	protected abstract String _structureName();

	protected final DataType _getCommonDataType(DataType libAttrType, boolean newname) {
		final DataType ubyte = Datatypes.u8, ushort = Datatypes.u16;

		StructureDataType common = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, "sceKernelLibraryEntryTable_ppu_common", 0);
		common.add(ubyte, "structsize", "Size of this structure");
		common.add(Datatypes.makeArray(ubyte, 1), "reserved1", "");
		common.add(ushort, "version", "Library version");
		common.add(libAttrType, "attribute", "Library attributes");
		common.add(ushort, "nfunc", "Number of exported functions");
		common.add(ushort, "nvar", "Number of exported variables");
		common.add(ushort, "ntlsvar", "Number of exported TLS variables");
		common.add(ubyte, "hashinfo", "Hash info (varinfo << 4 | funcinfo)");
		common.add(ubyte, "hashinfotls", "TLS hash info");
		common.add(Datatypes.makeArray(ubyte, 1), "reserved2", "");
		common.add(ubyte, "nidaltsets", "");

		if (!newname) {
			return common;
		}

		return new TypedefDataType(Datatypes.SCE_TYPES_CATPATH, "sceKernelLibraryEntryTable_prx2_common", common);
	}

	protected byte auxattribute;
	protected int version;
	protected int attribute;
	protected int nfunc;
	protected int nvar;
	protected int ntlsvar;
	protected short hashinfo;
	protected short hashinfotls;
	protected short nidaltsets;

	// For both tables, the content is concatenation of functions,
	// variables and TLS variables exports, in this order.
	//
	// The entry table holds pointers to the functions or the variables.
	protected int nidtable;
	protected int addtable;

	protected int libname_nid;
	protected int libname;

	public int getVersion() {
		return version;
	}

	public int getAttributes() {
		return attribute;
	}

	public int getExportsCount() {
		return nfunc + nvar + ntlsvar;
	}

	public int getFunctionsCount() {
		return nfunc;
	}

	public int getVariablesCount() {
		return nvar;
	}

	public int getTLSVariablesCount() {
		return ntlsvar;
	}

	public int getNIDTableVA() {
		return nidtable;
	}

	public int getEntryTableVA() {
		return addtable;
	}

	public int getLibraryNID() {
		return libname_nid;
	}

	public int getLibraryNameVA() {
		return libname;
	}

	// Filled during processing.
	private String libraryName = null;
	private Namespace libraryNS = null;
	private ArmElfPrxLoaderContext ctx;

	public abstract DataType toDataType(DataType libraryAttributesType);

	private static final int module_info_NID = 0x6C2224BA; // type: SceModuleInfo
	private static final int module_proc_param_NID = 0x70FBA1E7; // type: SceProcessParam
	private static final int module_sdk_version_NID = 0x936C8A78; // type: SceUInt32
	private static final int module_dtrace_probes_NID = 0x8CE938B1; // type: sdt_probedesc_t
	private static final int module_dtrace_probes_info_NID = 0x9318D9DD; // type: sdt_probes_info_t
	private static final int sce_module_start_thread_parameter_NID = 0x1A9822A4; // type: SceModuleThreadParameter
	private static final int sce_module_stop_thread_parameter_NID = 0xD20886EB; // type: SceModuleThreadParameter

	//For static DTrace probes processing
	private static final int SDT_PROBEDESC_VERSION = 1;
	private int dtrace_probes_va = 0, dtrace_probes_info_va = 0;

	//For thread parameter processing
	private int module_start_va = 0, module_stop_va = 0;
	private int module_start_thread_parameter_va = 0, module_stop_thread_parameter_va = 0;

	private void processStaticProbes() throws Exception {
		int probes_count = 0;
		{
			/*
			 * module_dtrace_probes_info is:
			 *
			 * typedef struct sdt_probes_info { unsigned int version; unsigned int count; }
			 * sdt_probes_info_t;
			 */
			StructureDataType probesInfoType = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, "sdt_probes_info_t",
					0);
			probesInfoType.add(Datatypes.u32, "version", "Probes version (should be 1)");
			probesInfoType.add(Datatypes.u32, "count", "Number of probes defined in module");

			Address probesInfoAddr = ctx.getAddressInDefaultAS(dtrace_probes_info_va);
			BinaryReader probesInfoReader = ctx.getBinaryReader(probesInfoAddr);
			ctx.createLabeledDataInNamespace(probesInfoAddr, ctx.moduleNamespace, "module_dtrace_probes_info",
					probesInfoType);

			final int probe_desc_version = probesInfoReader.readNextInt();
			if (probe_desc_version != SDT_PROBEDESC_VERSION) {
				ctx.logger.appendMsg(
						String.format("WARNING: ignoring static probes in module %s with incorrect version  (%d != %d)",
								probe_desc_version, SDT_PROBEDESC_VERSION));
				return;
			}

			probes_count = probesInfoReader.readNextInt();
		}

		IntBuffer probePointerTable;
		{
			Address probesAddr = ctx.getAddressInDefaultAS(dtrace_probes_va);
			BinaryReader probesReader = ctx.getBinaryReader(probesAddr);
			int probes_found = 0;

			for (probes_found = 0; probes_found <= probes_count /* include NULL entry in count */; probes_found++) {
				// NULL entry should be caught by this, ensuring counted_probes doesn't go over
				// expected_probes.
				// Of course, if the table is malformed, it will not and corruption will be
				// reported later on.
				if (probesReader.readNextInt() == 0) {
					break;
				}
			}

			if (probes_found != probes_count) {
				ctx.logger.appendMsg(String.format("WARNING: module static probe count mismatch (%d != %d)",
						probes_found, probes_count));
				return;
			}

			probePointerTable = ctx.readIntTable(probesAddr, probes_found);
		}

		for (int i = 0; i < probes_count; i++) {
			Address probeDescAddress = ctx.getAddressInDefaultAS(probePointerTable.get(i));
			BinaryReader probeDescReader = ctx.getBinaryReader(probeDescAddress);
			new sdt_probedesc_t(probeDescReader).process(ctx, probeDescAddress);
		}

		ctx.logger.appendMsg("module defines " + probes_count + " static probes");
	}

	private boolean processThreadParameter(String name, int mtpVA, int epVA) throws Exception {
		if (mtpVA != 0) {
			Address mtpAddr = ctx.getAddressInDefaultAS(mtpVA);
			SceModuleThreadParameter mtp = new SceModuleThreadParameter(ctx.getBinaryReader(mtpAddr), name);
			mtp.process(ctx, mtpAddr);

			if (epVA == 0) {
				ctx.logf("Module has sce_%s_thread_parameter but no %s function!", name, name);
			} else {
				mtp.addCommentToEntrypoint(ctx, epVA);
			}
			return true;
		}
		return false;
	}

	private void processThreadParameters() throws Exception {
		boolean hasThreadParameter = false;
		hasThreadParameter |= processThreadParameter("module_start", module_start_thread_parameter_va, module_start_va);
		hasThreadParameter |= processThreadParameter("module_stop", module_stop_thread_parameter_va, module_stop_va);

		//Only .suprx should have thread parameters, because it is ignored
		//for .skprx, and .self has dedicated (xxxMainThread) settings instead.
		if (hasThreadParameter) {
			ctx.setFileKind(ArmElfPrxLoaderContext.FILE_KIND_USERMOD);
		}
	}

	private void processMAINEXPORTVariable(int nid, int va) throws Exception {
		final Address varAddr = ctx.getAddressInDefaultAS(va);

		// Java doesn't allow switch on long...
		if (nid == module_info_NID) {
			// Nothing needs to be done, because the SceModuleInfo object has already been found and parsed.
		} else if (nid == module_proc_param_NID) {
			//Only apps can have a SceProcessParam
			ctx.setFileKind(ArmElfPrxLoaderContext.FILE_KIND_APP);
			SceProcessParam processParam = new SceProcessParam(ctx.getBinaryReader(varAddr));
			processParam.process(ctx, varAddr);
			ctx.setProcessParamSDKVersion(processParam.sdkVersion);
			ctx.createLabeledDataInNamespace(varAddr, ctx.moduleNamespace, "__sce_process_param", processParam.toDataType());
		} else if (nid == module_sdk_version_NID) {
			ctx.createLabeledDataInNamespace(varAddr, ctx.moduleNamespace, "module_sdk_version", Datatypes.u32);
			ctx.setModuleSDKVersion(ctx.memory.getInt(varAddr));
		} else if (nid == module_dtrace_probes_NID) {
			// We need both DTrace probes variables to process them.
			// Cache them for processMAINEXPORT() to process them later on.
			dtrace_probes_va = va;
		} else if (nid == module_dtrace_probes_info_NID) {
			dtrace_probes_info_va = va;
		} else if (nid == sce_module_start_thread_parameter_NID) {
			module_start_thread_parameter_va = va;
		} else if (nid == sce_module_stop_thread_parameter_NID) {
			module_stop_thread_parameter_va = va;
		} else {
			ctx.logger.appendMsg(String.format("Found MAINEXPORT variable with non-existent NID 0x%08X - skipped.", nid));
		}
	}

	private static final int module_start_NID = 0x935CD196;
	private static final int module_stop_NID = 0x79F8E492;
	private static final int module_exit_NID = 0x913482A9;
	private static final int module_bootstart_NID = 0x5C424D40;
	private static final int module_proc_create_NID = 0xE640E30C;
	private static final int module_proc_exit_NID = 0x4F0EE5BD;
	private static final int module_proc_kill_NID = 0xDF0212B9;
	private static final int module_suspend_NID = 0xDD42FA37;

	private static final Map<Integer, String> MAINEXPORT_lib_NID_to_function_name_map = Map.of(
			module_start_NID, "module_start",
			module_stop_NID, "module_stop",
			module_exit_NID, "module_exit",
			module_bootstart_NID, "module_bootstart",
			module_proc_create_NID, "module_proc_create",
			module_proc_exit_NID, "module_proc_exit",
			module_proc_kill_NID, "module_proc_kill",
			module_suspend_NID, "module_suspend"
	);

	private FunctionDefinitionDataType getMAINEXPORTFunctionSignature(int nid) {
		DataType u32 = Datatypes.u32;
		DataType s32 = Datatypes.s32;
		DataType ptr = Datatypes.ptr;

		FunctionDefinitionDataType dt = null;
		switch(nid) {
		case module_start_NID:
			dt = Datatypes.createFunctionDT(Datatypes.SCE_TYPES_CATPATH,
					s32, "module_start", Map.entry(u32, "arglen"), Map.entry(ptr, "argp"));
			break;
		case module_stop_NID:
			dt = Datatypes.createFunctionDT(Datatypes.SCE_TYPES_CATPATH,
					s32, "module_stop",	Map.entry(u32, "arglen"), Map.entry(ptr, "argp"));
			break;
		case module_exit_NID:
			dt = Datatypes.createFunctionDT(Datatypes.SCE_TYPES_CATPATH,
					s32, "module_exit",	Map.entry(u32, "arglen"), Map.entry(ptr, "argp"));
			break;
		case module_bootstart_NID:
			dt = Datatypes.createFunctionDT(Datatypes.SCE_TYPES_CATPATH,
					s32, "module_bootstart", Map.entry(u32, "arglen"), Map.entry(ptr, "argp"));
			break;
		case module_proc_create_NID:
			dt = Datatypes.createFunctionDT(Datatypes.SCE_TYPES_CATPATH,
					s32, "module_proc_create", Map.entry(s32, "pid"), Map.entry(ptr, "pParam"), Map.entry(ptr, "pCommon"));
			break;
		case module_proc_exit_NID:
			dt = Datatypes.createFunctionDT(Datatypes.SCE_TYPES_CATPATH,
					s32, "module_proc_exit", Map.entry(s32, "pid"), Map.entry(ptr, "pParam"), Map.entry(ptr, "pCommon"));
			break;
		case module_proc_kill_NID:
			dt = Datatypes.createFunctionDT(Datatypes.SCE_TYPES_CATPATH,
					s32, "module_proc_kill", Map.entry(s32, "pid"), Map.entry(ptr, "pParam"), Map.entry(ptr, "pCommon"));
			break;
		case module_suspend_NID:
			dt = Datatypes.createFunctionDT(Datatypes.SCE_TYPES_CATPATH,
					s32, "module_suspend");
			break;
		}

		return dt;
	}

	private void processMAINEXPORTFunction(int funcNID, int funcVA) throws Exception {
		String name = MAINEXPORT_lib_NID_to_function_name_map.get(funcNID);
		if (name == null) {
			// HACK: in 0.931, some modules have static probes exported as functions!
			if (funcNID == module_dtrace_probes_NID || funcNID == module_dtrace_probes_info_NID) {
				processMAINEXPORTVariable(funcNID, funcVA);
				return;
			}

			ctx.logf("Found MAINEXPORT function with non-existent NID 0x%08X - skipped.", funcNID);
			return;
		}

		Address funcAddr = ctx.getAddressInDefaultAS(funcVA & ~1); // Clear Thumb bit
		Function func = ctx.markupFunction(name, funcVA, null);
		ctx.symTbl.addExternalEntryPoint(funcAddr);

		FunctionDefinitionDataType signature = getMAINEXPORTFunctionSignature(funcNID);
		if (signature != null) {
			ctx.setFunctionSignature(func, signature);
		}


		//Stash module_start and module_stop VA for thread parameters markup
		if (funcNID == module_start_NID)
			module_start_va = funcVA;
		else if (funcNID == module_stop_NID)
			module_stop_va = funcVA;
	}

	private void processMAINEXPORTLibrary(Address libentAddress) throws Exception {
		ctx.monitor.checkCancelled();

		// (1) Prepare library name and namespace
		libraryName = "NONAME";
		libraryNS = ctx.moduleNamespace;

		// (2) Markup the libent in the listing
		ctx.createLabeledDataInNamespace(libentAddress, ctx.moduleNamespace, _structureName(),
				this.toDataType(ctx.libraryAttributesType));

		// (3) Markup and parse the export table
		final Address nidTblAddr = ctx.getAddressInDefaultAS(nidtable);
		final Address entTblAddr = ctx.getAddressInDefaultAS(addtable);

		if (ntlsvar != 0) {
			ctx.logger.appendMsg("MAINEXPORT export library reports TLS variables !");
		}

		final int nExports = nfunc + nvar;
		ctx.createLabeledDataInNamespace(nidTblAddr, ctx.moduleNamespace, "_MAINEXPORT_nid_table",
				Datatypes.makeArray(Datatypes.u32, nExports));
		ctx.createLabeledDataInNamespace(entTblAddr, ctx.moduleNamespace, "_MAINEXPORT_entry_table",
				Datatypes.makeArray(Datatypes.ptr, nExports));

		IntBuffer nidTable = ctx.readIntTable(nidTblAddr, nExports);
		IntBuffer entTable = ctx.readIntTable(entTblAddr, nExports);
		for (int i = 0; i < nfunc; i++) {
			ctx.monitor.checkCancelled();
			final int funcNID = nidTable.get(i), funcVA = entTable.get(i);
			processMAINEXPORTFunction(funcNID, funcVA);
		}

		for (int i = nfunc; i < nExports; i++) {
			ctx.monitor.checkCancelled();
			final int varNID = nidTable.get(i), varVA = entTable.get(i);
			processMAINEXPORTVariable(varNID, varVA);
		}

		// Process static probes after all variables have been processed
		if (dtrace_probes_va != 0 && dtrace_probes_info_va == 0) {
			ctx.logger.appendMsg("WARNING: module exports static probes info but not probes");
		} else if (dtrace_probes_va == 0 && dtrace_probes_info_va != 0) {
			ctx.logger.appendMsg("WARNING: module exports static probes but not probes info");
		} else if (dtrace_probes_va != 0 && dtrace_probes_info_va != 0) {
			processStaticProbes();
		}

		//Process thread parameters after all variables have been processed too
		processThreadParameters();
	}

	private String generateExportPlateComment(String kind, int importNID) {
		String comment = "--- EXPORTED " + kind.toUpperCase() + " ---\n";
		comment += "Library: " + libraryName;
		if (libname_nid != ILibstub.UNKNOWN_NID) {
			comment += String.format(" (NID 0x%08X)\n", libname_nid);
		} else {
			comment += "\n";
		}

		if ((attribute & SELFConstants.SCE_LIBRARY_ATTR_SYSCALL_EXPORT) != 0) {
			comment += "Syscall exported function\n";
		}

		comment += String.format("%s NID: 0x%08X\n", kind, importNID);
		comment += String.format("--- %s ---", Utils.getSystematicName(libraryName, importNID));
		return comment;
	}

	private void processFunction(int nid, int va) throws Exception {
		final String name = Utils.getSystematicName(libraryName, nid);
		final Address funcAddr = ctx.getAddressInDefaultAS(va & ~1); // Clear Thumb bit
		String comment = generateExportPlateComment("Function", nid);

		// Markup the function, and add as entrypoint if function didn't already exist.
		boolean needsEntrypointMarkup = (ctx.funcMgr.getFunctionAt(funcAddr) == null);
		ctx.markupFunction(name, va, comment);
		if (needsEntrypointMarkup) {
			ctx.symTbl.addExternalEntryPoint(funcAddr);
		}
		ctx.addImportExportEntry(funcAddr, libraryName, nid, ArmElfPrxLoaderContext.IETYPE_EXPORT, ArmElfPrxLoaderContext.IEKIND_FUNC);
	}

	private void processVariable(int nid, int va, boolean tls) throws Exception {
		final String name = Utils.getSystematicName(libraryName, nid);
		final Address varAddr = ctx.getAddressInDefaultAS(va);
		if (!ctx.memory.contains(varAddr)) {
			// Some modules (e.g. SceKernelPsp2Config) export variables that are outside the
			// modules. Simply log a message but skip processing these variables to avoid
			// catastrophic failures.
			ctx.logger.appendMsg(String.format("Skipped exported variable %s: address 0x%08X not in memory.", name, va));
			return;
		}

		String comment = generateExportPlateComment(tls ? "TLS Variable" : "Variable", nid);

		if (ctx.flatAPI.getSymbolAt(varAddr) != null) {
			String oldComment = ctx.flatAPI.getPlateComment(varAddr);
			if (oldComment != null) {
				comment = oldComment + "\n\n" + comment;
			}
		}
		ctx.flatAPI.createLabel(varAddr, name, false);
		ctx.flatAPI.setPlateComment(varAddr, comment);
		ctx.addImportExportEntry(varAddr, libraryName, nid, ArmElfPrxLoaderContext.IETYPE_EXPORT,
				tls ? ArmElfPrxLoaderContext.IEKIND_TLSVAR : ArmElfPrxLoaderContext.IEKIND_VAR);
	}

	public void process(ArmElfPrxLoaderContext processingContext, Address libentAddress) throws Exception {
		// (0) Verify sanity. SYSCALL_EXPORT libraries are not allowed to export variables.
		if ((attribute & SELFConstants.SCE_LIBRARY_ATTR_SYSCALL_EXPORT) != 0
				&& (nvar != 0 || ntlsvar != 0)) {
			throw new MalformedElfException("SYSCALL_EXPORT library exports variables");
		}

		ctx = processingContext;
		ctx.monitor.checkCancelled();
		if ((getAttributes() & SELFConstants.SCE_LIBRARY_ATTR_MAIN_EXPORT) != 0) {
			processMAINEXPORTLibrary(libentAddress);
			return;
		}

		// (1) Read the library's name
		final Address libNameAddr = ctx.getAddressInDefaultAS(libname);
		{
			BinaryReader nameReader = ctx.getBinaryReader(libNameAddr);
			libraryName = nameReader.readNextAsciiString();
		}

		// (2) Create a namespace for the library
		libraryNS = ctx.getOrCreateNamespace(null, "+" + libraryName);

		// (3) Markup the libent and library name in the listing
		ctx.createLabeledDataInNamespace(libentAddress, libraryNS, _structureName(),
				this.toDataType(ctx.libraryAttributesType));
		ctx.createLabeledDataInNamespace(libNameAddr, libraryNS, "_" + libraryName + "_stub_str",
				new TerminatedStringDataType());

		// (4) Markup and parse the export table
		// The NID table is a contiguous array of NIDs, while the entry table is a
		// contiguours array of pointers.
		// The order is functions first, followed by variables then TLS variables.
		final Address nidTblAddr = ctx.getAddressInDefaultAS(nidtable);
		final Address entTblAddr = ctx.getAddressInDefaultAS(addtable);

		final int nExports = nfunc + nvar + ntlsvar;
		// TODO: are these names correct?
		ctx.createLabeledDataInNamespace(nidTblAddr, libraryNS, "_" + libraryName + "_nidtable",
				Datatypes.makeArray(Datatypes.u32, nExports));
		ctx.createLabeledDataInNamespace(entTblAddr, libraryNS, "_" + libraryName + "_addtable",
				Datatypes.makeArray(Datatypes.ptr, nExports));

		IntBuffer nidTable = ctx.readIntTable(nidTblAddr, nExports);
		IntBuffer entTable = ctx.readIntTable(entTblAddr, nExports);
		for (int i = 0; i < nfunc; i++) {
			ctx.monitor.checkCancelled();
			final int funcNID = nidTable.get(i), funcVA = entTable.get(i);
			processFunction(funcNID, funcVA);
		}
		for (int i = nfunc; i < (nfunc + nvar); i++) {
			ctx.monitor.checkCancelled();
			final int varNID = nidTable.get(i), varVA = entTable.get(i);
			processVariable(varNID, varVA, false);
		}
		for (int i = (nfunc + nvar); i < nExports; i++) {
			ctx.monitor.checkCancelled();
			final int TLSVarNID = nidTable.get(i), TLSVarVA = entTable.get(i);
			processVariable(TLSVarNID, TLSVarVA, true);
		}
	}
}
