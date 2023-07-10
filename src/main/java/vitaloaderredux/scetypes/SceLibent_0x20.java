package vitaloaderredux.scetypes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;

//Used since firmware 0.940
public class SceLibent_0x20 extends ILibent {
	public static final int SIZE = 0x20;
	
	public SceLibent_0x20(BinaryReader reader) throws IOException {
		final int structureSize = reader.readNextByte();
		if (structureSize != SIZE) {
			throw new MalformedElfException(String.format("Invalid Libent size! (0x%X != 0x%X)", structureSize, SIZE));
		}
		
		auxattribute = reader.readNextByte();
		version[0] = reader.readNextByte();
		version[1] = reader.readNextByte();
		attributes = reader.readNextUnsignedShort();
		nFunctions = reader.readNextUnsignedShort();
		nVariables = reader.readNextUnsignedShort();
		nTLSVariables = reader.readNextUnsignedShort();
		hashinfo = reader.readNextByte();
		hashinfotls = reader.readNextByte();
		byte reserved_0xD = reader.readNextByte();
		nidaltsets = reader.readNextByte();
		
		libraryNID = reader.readNextInt();
		libraryNameAddress = reader.readNextInt();
		
		NIDTableAddress = reader.readNextInt();
		entryTableAddress = reader.readNextInt();
		
		if (reserved_0xD != 0) {
			System.out.println(String.format("Library with NID 0x%08X has non-zero reserved_0xD (0x%08X).", libraryNID, reserved_0xD));
		}
		
		Utils.assertBRSize(STRUCTURE_NAME, reader, SIZE);
	}

	@Override
	public DataType toDataType(DataType libraryAttributesType) {
		if (DATATYPE == null) {
			DATATYPE = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
			DATATYPE.add(Datatypes.u8, "size", "Size of this structure");
			DATATYPE.add(Datatypes.u8, "auxattribute", null);
			DATATYPE.add(Datatypes.makeArray(Datatypes.u8, 2), "version", "Library version [major.minor]");
			DATATYPE.add(libraryAttributesType, "attributes", "Library attributes");
			DATATYPE.add(Datatypes.u16, "num_functions", "Number of functions exported by this library");
			DATATYPE.add(Datatypes.u16, "num_variables", "Number of variables exported by this library");
			DATATYPE.add(Datatypes.u16, "num_tls_variables", "Number of TLS variables exported by this library");
			DATATYPE.add(Datatypes.u8, "hashinfo", "Hash info of (num_variables << 4 | num_functions)");
			DATATYPE.add(Datatypes.u8, "hashinfotls", "Hash info of num_tls_variables");
			DATATYPE.add(Datatypes.u8, "reserved_0xD", "Reserved?");
			DATATYPE.add(Datatypes.u8, "nidaltsets", null);
			DATATYPE.add(Datatypes.u32, "library_nid", "Numeric Identifier (NID) of this library");
			DATATYPE.add(Datatypes.stringptr, "library_name", "Pointer to the library's name");
			DATATYPE.add(Datatypes.u32ptr, "nid_table", "Pointer to the library's NID table");
			DATATYPE.add(Datatypes.ptr_to_ptr, "entry_table", "Pointer to the library's entry table");
			
			Utils.assertStructureSize(DATATYPE, SIZE);
		}
		return DATATYPE;
	}
	private StructureDataType DATATYPE;
}
