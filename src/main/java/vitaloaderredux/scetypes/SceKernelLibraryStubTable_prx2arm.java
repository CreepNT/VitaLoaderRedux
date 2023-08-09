package vitaloaderredux.scetypes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;

//First libstub available in PRX2 format. Superseded by the 0x24-sized variant.
public class SceKernelLibraryStubTable_prx2arm extends ILibstub {
	public static final String STRUCTURE_NAME = "sceKernelLibraryStubTable_prx2arm";
	public static final int SIZE = 0x34;
	
	@Override
	protected String _structureName() { return STRUCTURE_NAME; }

	
	public SceKernelLibraryStubTable_prx2arm(BinaryReader reader) throws IOException {
		final int structureSize = reader.readNextUnsignedShort();
		if (structureSize != SIZE) {
			throw new MalformedElfException(String.format("Invalid Libstub size (0x%X != 0x%X)", structureSize, SIZE));
		}
		
		version = reader.readNextUnsignedShort();
		attribute = reader.readNextUnsignedShort();
		nfunc = reader.readNextUnsignedShort();
		nvar = reader.readNextUnsignedShort();
		ntlsvar = reader.readNextUnsignedShort();
		reader.readNextInt(); //reserved1
		libname_nid = reader.readNextInt();
		libname = reader.readNextInt();
		reader.readNextInt(); //reserved2
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
			DATATYPE.add(_getCommonDataType(libraryAttributesType, true));
			DATATYPE.add(Datatypes.u32, "libname_nid", "NID corresponding to library name");
			DATATYPE.add(Datatypes.stringptr, "libname", "Pointer to library's name");
			DATATYPE.add(Datatypes.u32, "sce_sdk_version", "");
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
