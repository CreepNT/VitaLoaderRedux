package vitaloaderredux.scetypes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;

//Used in PRX1 format
public class SceKernelLibraryStubTable_arm extends ILibstub {
	public static final String STRUCTURE_NAME = "sceKernelLibraryStubTable_arm";
	public static final int SIZE = 0x2C;

	@Override
	protected String _structureName() { return STRUCTURE_NAME; }

	public SceKernelLibraryStubTable_arm(BinaryReader reader) throws IOException {
		final int structureSize = reader.readNextUnsignedShort();
		if (structureSize != SIZE) {
			throw new MalformedElfException(String.format("Invalid Libstub size (0x%X != 0x%X)", structureSize, SIZE));
		}

		//We could try retrieving the library NID, located at (libraryNameAddress - 0x8).
		//However, in firmware 0.902 (and 0.920?), there are actually no NIDs stored there.
		//Since we match libraries based on name (and not NID) anyways,
		//we don't really care about this, so return UNKNOWN_NID.
		libname_nid = ILibstub.UNKNOWN_NID;

		version = reader.readNextUnsignedShort();
		attribute = reader.readNextUnsignedShort();

		nfunc = reader.readNextUnsignedShort();
		nvar = reader.readNextUnsignedShort();
		ntlsvar = reader.readNextUnsignedShort();

		reader.readNextInt(); //reserved2
		libname = reader.readNextInt();

		func_nidtable = reader.readNextInt();
		func_table = reader.readNextInt();

		var_nidtable = reader.readNextInt();
		var_table = reader.readNextInt();

		tls_nidtable = reader.readNextInt();
		tls_table = reader.readNextInt();

		Utils.assertBRSize(STRUCTURE_NAME, reader, SIZE);
	}

//ILibstub
	@Override
	public DataType toDataType(DataType libraryAttributesType) {
		if (DATATYPE == null) {
			DATATYPE = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
			DATATYPE.add(_getCommonDataType(libraryAttributesType, false));
			DATATYPE.add(Datatypes.stringptr, "libname", "Pointer to library's name");
			DATATYPE.add(Datatypes.u32ptr, "func_nidtable", "Pointer to functions NID table");
			DATATYPE.add(Datatypes.ptr_to_ptr, "func_table", "Pointer to functions table");
			DATATYPE.add(Datatypes.u32ptr, "var_nidtable", "Pointer to variables NID table");
			DATATYPE.add(Datatypes.ptr_to_ptr, "var_table", "Pointer to variables table");
			DATATYPE.add(Datatypes.u32ptr, "tls_nidtable", "Pointer to TLS variables NID table");
			DATATYPE.add(Datatypes.ptr_to_ptr, "tls_table", "Pointer to TLS variables entry table");

			Utils.assertStructureSize(DATATYPE, SIZE);
		}
		return DATATYPE;
	}
	private StructureDataType DATATYPE;
}
