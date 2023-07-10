package vitaloaderredux.scetypes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;

//Used between firmwares ?1.xx? and ?3.xx?
public class SceLibstub_0x34 extends ILibstub {
	public static final int SIZE = 0x34;
	
	private final int TLSNIDTableAddress;
	private final int TLSEntryTableAddress;
	
	public SceLibstub_0x34(BinaryReader reader) throws IOException {
		final int structureSize = reader.readNextUnsignedShort();
		if (structureSize != SIZE) {
			throw new MalformedElfException(String.format("Invalid Libstub size (0x%X != 0x%X)", structureSize, SIZE));
		}
		
		version[0] = reader.readNextByte();
		version[1] = reader.readNextByte();
		attributes = reader.readNextUnsignedShort();
		nFunctions = reader.readNextUnsignedShort();
		nVariables = reader.readNextUnsignedShort();
		nTLSVariables = reader.readNextUnsignedShort();
		final int reserved1 = reader.readNextInt();
		libraryNID = reader.readNextInt();
		libraryNameVA = reader.readNextInt();
		final int reserved2 = reader.readNextInt();
		functionNIDTableVA = reader.readNextInt();
		functionEntryTableVA = reader.readNextInt();
		variableNIDTableVA = reader.readNextInt();
		variableEntryTableVA = reader.readNextInt();
		TLSNIDTableAddress = reader.readNextInt();
		TLSEntryTableAddress = reader.readNextInt();
		
		if (reserved1 != 0) {
			System.out.println(String.format("Library with NID 0x%08X has non-zero reversed1 (0x%08X).", libraryNID, reserved1));
		}
		if (reserved2 != 0) {
			System.out.println(String.format("Library with NID 0x%08X has non-zero reversed2 (0x%08X).", libraryNID, reserved2));
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
			DATATYPE.add(Datatypes.u32, "library_nid", "Numeric Identifier (NID) of this library");
			DATATYPE.add(Datatypes.stringptr, "library_name", "Pointer to library name");
			DATATYPE.add(Datatypes.u32, "reserved_0x18", "Reserved?");
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
	private StructureDataType DATATYPE;

}
