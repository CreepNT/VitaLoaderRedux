package vitaloaderredux.scetypes;

import java.io.IOException;
import java.nio.IntBuffer;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;

import vitaloaderredux.loader.ArmElfPrxLoaderContext;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;

public abstract class ILibstub {
	public static final String STRUCTURE_NAME = "SceLibstub";

	// Library NID returned when it cannot be obtained.
	// In theory, a library could have this value as its NID,
	// however the chances of this happening as so small this
	// that this will Probably Never� cause any problem.
	public static final int UNKNOWN_NID = 0xFFFFFFFF;

	protected byte[] version = new byte[2];

	protected int attributes;

	protected int nFunctions;
	protected int nVariables;
	protected int nTLSVariables;

	protected int libraryNID;
	protected int libraryNameVA;

	protected int functionNIDTableVA;
	protected int functionEntryTableVA;

	protected int variableNIDTableVA;
	protected int variableEntryTableVA;

	public byte[] getVersion() {
		return version.clone();
	}

	public int getAttributes() {
		return attributes;
	}

	public int getLibraryNameVA() {
		return libraryNameVA;
	}

	public int getLibraryNID() {
		return libraryNID;
	}

	public int getFunctionsCount() {
		return nFunctions;
	}

	public int getFunctionsNIDTableAddress() {
		return functionNIDTableVA;
	}

	public int getFunctionsEntryTableAddress() {
		return functionEntryTableVA;
	}

	public int getVariablesCount() {
		return nVariables;
	}

	public int getVariablesNIDTableAddress() {
		return variableNIDTableVA;
	}

	public int getVariablesEntryTableAddress() {
		return variableEntryTableVA;
	}

	public int getTLSVariablesCount() {
		return nTLSVariables;
	}

	public abstract int getTLSVariablesNIDTableAddress();

	public abstract int getTLSVariablesEntryTableAddress();

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
		if (libraryNID != ILibstub.UNKNOWN_NID) {
			comment += String.format(" (NID 0x%08X)\n", libraryNID);
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

		ctx.createLabeledDataInNamespace(nidTblAddr, libraryNS, "__" + libraryName + "_" + kind + "_nid_table",
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
		ctx.createLabeledDataInNamespace(libstubAddress, libraryNS, STRUCTURE_NAME,
				this.toDataType(ctx.libraryAttributesType));
		ctx.createLabeledDataInNamespace(libNameAddr, libraryNS, "_" + libraryName + "_stub_str",
				new TerminatedStringDataType());

		// (4) Parse the libstub tables
		if (nFunctions > 0) {
			markupAndProcessTable(functionNIDTableVA, functionEntryTableVA, nFunctions, "func",
					(nid, va) -> markupFuncImportAndProcessRela(nid, va));
		}

		if (nVariables > 0) {
			markupAndProcessTable(variableNIDTableVA, variableEntryTableVA, nVariables, "var",
					(nid, va) -> markupVarImportAndProcessRela(nid, va, false));
		}

		if (nTLSVariables > 0) {
			int NIDTableVA = getTLSVariablesNIDTableAddress(), entTableVA = getTLSVariablesEntryTableAddress();
			markupAndProcessTable(NIDTableVA, entTableVA, nTLSVariables, "tls_var",
					(nid, va) -> markupVarImportAndProcessRela(nid, va, true));
		}
	}
}
