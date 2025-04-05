package vitaloaderredux.scetypes;

import java.io.IOException;
import java.nio.IntBuffer;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import vitaloaderredux.loader.ArmElfPrxLoaderContext;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;

public abstract class ILibstub {
	// Library NID returned when it cannot be obtained.
	// In theory, a library could have this value as its NID,
	// however the chances of this happening as so small this
	// that this will Probably Never� cause any problem.
	public static final int UNKNOWN_NID = 0xFFFFFFFF;

	protected abstract String _structureName();

	protected final DataType _getCommonDataType(DataType libAttrType, boolean newname) {
		final DataType ubyte = Datatypes.u8, ushort = Datatypes.u16;

		StructureDataType common = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, "sceKernelLibraryStubTable_ppu_common", 0);
		common.add(ubyte, "structsize", "Size of this structure");
		common.add(Datatypes.makeArray(ubyte, 1), "reserved1", "");
		common.add(ushort, "version", "Library version");
		common.add(libAttrType, "attribute", "Library attributes");
		common.add(ushort, "nfunc", "Number of functions imported from this library");
		common.add(ushort, "nvar", "Number of variables imported from this library");
		common.add(ushort, "ntlsvar", "Number of TLS variables imported from this library");
		common.add(Datatypes.makeArray(ubyte, 4), "reserved2", "");

		if (!newname) {
			return common;
		}

		return new TypedefDataType(Datatypes.SCE_TYPES_CATPATH, "sceKernelLibraryStubTable_prx2_common", common);
	}

	protected int version;
	protected int attribute;

	protected int nfunc;
	protected int nvar;
	protected int ntlsvar;

	protected int libname_nid;
	protected int libname;

	protected int func_nidtable;
	protected int func_table;

	protected int var_nidtable;
	protected int var_table;

	protected int tls_nidtable;
	protected int tls_table;

	public int getVersion() {
		return version;
	}

	public int getAttributes() {
		return attribute;
	}

	public int getLibraryNameVA() {
		return libname;
	}

	public int getLibraryNID() {
		return libname_nid;
	}

	public int getFunctionsCount() {
		return nfunc;
	}

	public int getFunctionsNIDTableAddress() {
		return func_nidtable;
	}

	public int getFunctionsEntryTableAddress() {
		return func_table;
	}

	public int getVariablesCount() {
		return nvar;
	}

	public int getVariablesNIDTableAddress() {
		return var_nidtable;
	}

	public int getVariablesEntryTableAddress() {
		return var_table;
	}

	public int getTLSVariablesCount() {
		return ntlsvar;
	}

	public int getTLSVariablesNIDTableAddress() {
		return tls_nidtable;
	}

	public int getTLSVariablesEntryTableAddress() {
		return tls_table;
	}

	public abstract DataType toDataType(DataType libraryAttributesType);

	// Populated during processing.
	private String libraryName = null;
	private Namespace libraryNS = null;
	private ArmElfPrxLoaderContext ctx = null;

	private interface TableProcessingCallback {
		void execute(int nid, int va) throws Exception;
	}

	private String generateImportPlateComment(String kind, String moduleFileName, int importNID) {
		if (moduleFileName == null)
			moduleFileName = "<unknown>";

		String comment = "--- IMPORTED " + kind.toUpperCase() + " ---\n";
		comment += "Imported from " + moduleFileName + "\n";
		comment += "Library: " + libraryName;
		if (libname_nid != ILibstub.UNKNOWN_NID) {
			comment += String.format(" (NID 0x%08X)\n", libname_nid);
		} else {
			comment += "\n";
		}

		comment += String.format("%s NID: 0x%08X\n", kind, importNID);
		comment += String.format("--- %s ---", Utils.getSystematicName(libraryName, importNID));
		return comment;
	}

	private void markupFuncImportAndProcessRela(int nid, int va) throws Exception {
		final String modFileName = ctx.modFileNameFromLibraryName(libraryName);
		final String funcName = Utils.getSystematicName(libraryName, nid);

		final Address funcAddr = ctx.getAddressInDefaultAS(va & ~1); // Clear Thumb bit
		Function func = ctx.markupFunction(funcName, va, generateImportPlateComment("Function", modFileName, nid));
		Function importStub = ctx.getImportFunction(modFileName, funcName);
		func.setThunkedFunction(importStub); // Mark as imported function
		ctx.addImportExportEntry(funcAddr, libraryName, nid, ArmElfPrxLoaderContext.IETYPE_IMPORT, ArmElfPrxLoaderContext.IEKIND_FUNC);

		// Process function relocations if any exist
		final int funcRelaVA = ctx.memory.getInt(funcAddr.add(3*4));
		if (funcRelaVA != 0) {
			ctx.createData(funcAddr.add(3*4), Datatypes.ptr);

			final Address relaAddr = ctx.getAddressInDefaultAS(funcRelaVA);
			ctx.listing.setComment(relaAddr, CodeUnit.PLATE_COMMENT, String.format("Relocation table for %s @ 0x%08X", funcName, va));
			ctx.relocator.processReftable(relaAddr, funcAddr);
		}
	}

	private void markupVarImportAndProcessRela(int nid, int va, boolean tls) throws Exception {
		final String modFileName = ctx.modFileNameFromLibraryName(libraryName);
		final String varName = Utils.getSystematicName(libraryName, nid);
		final Address relaAddr = ctx.getAddressInDefaultAS(va);

		//Allocate import variable slot and perform relocation towards it
		Address importVarAddr = ctx.relocator.allocateImportVariableSlot(libraryName, nid, tls);

		//Markup the table and add comment to table and variable
		ctx.listing.setComment(relaAddr, CodeUnit.PLATE_COMMENT, String.format("Relocation table for %s @ 0x%08X", varName, importVarAddr.getOffset()));

		String comment = generateImportPlateComment(tls ? "TLS Variable" : "Variable", modFileName, nid);
		ctx.listing.setComment(importVarAddr, CodeUnit.PLATE_COMMENT, comment);
		ctx.relocator.processReftable(relaAddr, importVarAddr);
	}

	private void markupAndProcessTable(int nidTableVA, int entryTableVA, int numElements, String kind,
			TableProcessingCallback callback) throws Exception {
		ctx.monitor.checkCancelled();

		Address nidTblAddr = ctx.getAddressInDefaultAS(nidTableVA);
		Address entTblAddr = ctx.getAddressInDefaultAS(entryTableVA);

		ctx.createLabeledDataInNamespace(nidTblAddr, libraryNS, "__" + libraryName + "_" + kind + "_nidtable",
				Datatypes.makeArray(Datatypes.u32, numElements));
		ctx.createLabeledDataInNamespace(entTblAddr, libraryNS, "__" + libraryName + "_" + kind + "_table",
				Datatypes.makeArray(Datatypes.ptr, numElements));

		IntBuffer nidTable = ctx.readIntTable(nidTblAddr, numElements);
		IntBuffer entTable = ctx.readIntTable(entTblAddr, numElements);

		for (int i = 0; i < numElements; i++) {
			ctx.monitor.checkCancelled();
			callback.execute(nidTable.get(i), entTable.get(i));
		}
	}

	// Reads the library's name into libraryName, and returns its Address.
	private Address readLibraryName() throws IOException {
		final Address libNameAddr = ctx.getAddressInDefaultAS(this.getLibraryNameVA());
		BinaryReader nameReader = ctx.getBinaryReader(libNameAddr);
		libraryName = nameReader.readNextAsciiString();

		return libNameAddr;
	}

	public void process(ArmElfPrxLoaderContext processingContext, Address libstubAddress) throws Exception {
		ctx = processingContext;
		ctx.monitor.checkCancelled();

		// (1) Read the library's name
		Address libNameAddr = readLibraryName();

		// (2) Create a namespace for the library
		libraryNS = ctx.getOrCreateNamespace(null, "-" + libraryName);

		// (3) Markup the libstub and library name in the listing
		ctx.createLabeledDataInNamespace(libstubAddress, libraryNS, _structureName(),
				this.toDataType(ctx.libraryAttributesType));
		ctx.createLabeledDataInNamespace(libNameAddr, libraryNS, "_" + libraryName + "_stub_str",
				new TerminatedStringDataType());

		// (4) Parse the libstub tables
		if (nfunc > 0) {
			markupAndProcessTable(func_nidtable, func_table, nfunc, "func",
					(nid, va) -> markupFuncImportAndProcessRela(nid, va));
		}

		if (nvar > 0) {
			markupAndProcessTable(var_nidtable, var_table, nvar, "var",
					(nid, va) -> markupVarImportAndProcessRela(nid, va, false));
		}

		if (ntlsvar > 0) {
			int NIDTableVA = getTLSVariablesNIDTableAddress(), entTableVA = getTLSVariablesEntryTableAddress();
			markupAndProcessTable(NIDTableVA, entTableVA, ntlsvar, "tls",
					(nid, va) -> markupVarImportAndProcessRela(nid, va, true));
		}
	}
}
