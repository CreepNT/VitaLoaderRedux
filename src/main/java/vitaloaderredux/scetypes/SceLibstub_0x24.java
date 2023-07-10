package vitaloaderredux.scetypes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;

public class SceLibstub_0x24 extends ILibstub {
	public static final int SIZE = 0x24;
	
	public SceLibstub_0x24(BinaryReader reader) throws IOException {
		final int size = reader.readNextUnsignedShort();
		if (size != SIZE) {
			throw new MalformedElfException(String.format("Invalid Libstub size (0x%X != 0x%X)", size, SIZE));
		}
		
		version[0] = reader.readNextByte();
		version[1] = reader.readNextByte();
		
		attributes = reader.readNextUnsignedShort();
		
		nFunctions = reader.readNextUnsignedShort();
		nVariables = reader.readNextUnsignedShort();
		nTLSVariables = reader.readNextUnsignedShort();
		
		libraryNID = reader.readNextInt();
		libraryNameVA = reader.readNextInt();
		
		functionNIDTableVA = reader.readNextInt();
		functionEntryTableVA = reader.readNextInt();
		
		variableNIDTableVA = reader.readNextInt();
		variableEntryTableVA = reader.readNextInt();
		
		Utils.assertBRSize(STRUCTURE_NAME, reader, size);
	}

//ILibstub
	//TODO: are both of these correct?!
	@Override
	public int getTLSVariablesEntryTableAddress() {
		if (nTLSVariables == 0)
			return 0;
		
		return variableEntryTableVA + 4 * nVariables;
	}
	
	@Override
	public int getTLSVariablesNIDTableAddress() {
		if (nTLSVariables == 0)
			return 0;
		
		return variableNIDTableVA + 4 * nVariables;
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
			DATATYPE.add(Datatypes.u32, "library_nid", "Numeric Identifier (NID) of this library");
			DATATYPE.add(Datatypes.stringptr, "library_name", "Pointer to library name");
			DATATYPE.add(Datatypes.u32ptr, "func_nid_table", "Pointer to functions NID table");
			DATATYPE.add(Datatypes.ptr_to_ptr, "func_entry_table", "Pointer to functions entry table");
			DATATYPE.add(Datatypes.u32ptr, "var_nid_table", "Pointer to variables NID table");
			DATATYPE.add(Datatypes.ptr_to_ptr, "var_entry_table", "Pointer to variables entry table");
			
			Utils.assertStructureSize(DATATYPE, SIZE);
		}
		return DATATYPE;
	}
	private StructureDataType DATATYPE;
}
