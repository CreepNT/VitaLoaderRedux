package vitaloaderredux.scetypes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;

//Used in firmware 0.902-0.931
public class SceLibstub_0x2C extends ILibstub {
	public static final int SIZE = 0x2C;

	private final int TLSNIDTableAddress;
	private final int TLSEntryTableAddress;

	public SceLibstub_0x2C(BinaryReader reader) throws IOException {
		final int structureSize = reader.readNextUnsignedShort();
		if (structureSize != SIZE) {
			throw new MalformedElfException(String.format("Invalid Libstub size (0x%X != 0x%X)", structureSize, SIZE));
		}
		
		//We could try retrieving the library NID, located at (libraryNameAddress - 0x8).
		//However, in firmware 0.902 (and 0.920?), there are actually no NIDs stored there.
		//Since we match libraries based on name (and not NID) anyways,
		//we don't really care about this, so return UNKNOWN_NID.
		libraryNID = ILibstub.UNKNOWN_NID;
		
		version[0] = reader.readNextByte();
		version[1] = reader.readNextByte();
		attributes = reader.readNextUnsignedShort();
		
		nFunctions = reader.readNextUnsignedShort();
		nVariables = reader.readNextUnsignedShort();
		nTLSVariables = reader.readNextUnsignedShort();
		
		final int reserved_0xC = reader.readNextInt();
		libraryNameVA = reader.readNextInt();
		
		functionNIDTableVA = reader.readNextInt();
		functionEntryTableVA = reader.readNextInt();
		
		variableNIDTableVA = reader.readNextInt();
		variableEntryTableVA = reader.readNextInt();
		
		TLSNIDTableAddress = reader.readNextInt();
		TLSEntryTableAddress = reader.readNextInt();
		
		if (reserved_0xC != 0) {
			System.err.println(String.format("Library with NID 0x%08X has non-zero reserved_0xC (0x%08X).", libraryNID, reserved_0xC));
		}
		
		Utils.assertBRSize(STRUCTURE_NAME, reader, SIZE);
	}

//ILibstub
	@Override
	public int getTLSVariablesNIDTableAddress() {
		return TLSNIDTableAddress;
	}

	@Override
	public int getTLSVariablesEntryTableAddress() {
		return TLSEntryTableAddress;
	}

	@Override
	public DataType toDataType(DataType libraryAttributesType) {
		if (DATATYPE == null) {
			DATATYPE = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
			DATATYPE.add(Datatypes.u16, "size", "Size of this structure");
			DATATYPE.add(Datatypes.makeArray(Datatypes.u8, 2), "version", "Library version [major.minor]");
			DATATYPE.add(libraryAttributesType, "attributes", "Library attributes");
			DATATYPE.add(Datatypes.u16, "num_functions", "Number of functions imported from this library");
			DATATYPE.add(Datatypes.u16, "num_variables", "Number of variables imported from this library");
			DATATYPE.add(Datatypes.u16, "num_tls_variables", "Number of TLS variables imported from this library");
			DATATYPE.add(Datatypes.u32, "reserved_0xC", "Reserved?");
			DATATYPE.add(Datatypes.stringptr, "library_name", "Pointer to library name");
			DATATYPE.add(Datatypes.u32ptr, "func_nid_table", "Pointer to functions NID table");
			DATATYPE.add(Datatypes.ptr_to_ptr, "func_entry_table", "Pointer to functions entry table");
			DATATYPE.add(Datatypes.u32ptr, "var_nid_table", "Pointer to variables NID table");
			DATATYPE.add(Datatypes.ptr_to_ptr, "var_entry_table", "Pointer to variables entry table");
			DATATYPE.add(Datatypes.u32ptr, "tls_nid_table", "Pointer to TLS variables NID table");
			DATATYPE.add(Datatypes.ptr_to_ptr, "tls_entry_table", "Pointer to TLS variables entry table");
			
			Utils.assertStructureSize(DATATYPE, SIZE);
		}
		return DATATYPE;
	}
	private static StructureDataType DATATYPE;
}
