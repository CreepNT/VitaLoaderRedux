package vitaloaderredux.scetypes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;

//Available in PRX2 format since firmware ?
public class SceKernelLibraryStubTable_0x24 extends ILibstub {
	public static final String STRUCTURE_NAME = "SceLibstub_0x24";
	public static final int SIZE = 0x24;

	@Override
	protected String _structureName() { return STRUCTURE_NAME; }

	public SceKernelLibraryStubTable_0x24(BinaryReader reader) throws IOException {
		final int size = reader.readNextUnsignedByte();
		if (size != SIZE) {
			throw new MalformedElfException(String.format("Invalid Libstub size (0x%X != 0x%X)", size, SIZE));
		}

		reader.readNextUnsignedByte(); //reserved1



		version = reader.readNextUnsignedShort();

		attribute = reader.readNextUnsignedShort();

		nfunc = reader.readNextUnsignedShort();
		nvar = reader.readNextUnsignedShort();
		ntlsvar = reader.readNextUnsignedShort();

		libname_nid = reader.readNextInt();
		libname = reader.readNextInt();

		func_nidtable = reader.readNextInt();
		func_table = reader.readNextInt();

		var_nidtable = reader.readNextInt();
		var_table = reader.readNextInt();

		Utils.assertBRSize(STRUCTURE_NAME, reader, size);
	}

//ILibstub
	//TODO: are both of these correct?!
	@Override
	public int getTLSVariablesEntryTableAddress() {
		if (ntlsvar == 0)
			return 0;

		return var_table + 4 * nvar;
	}

	@Override
	public int getTLSVariablesNIDTableAddress() {
		if (ntlsvar == 0)
			return 0;

		return var_nidtable + 4 * nvar;
	}


	@Override
	public DataType toDataType(DataType libraryAttributesType) {
		if (DATATYPE == null) {
			DATATYPE = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
			DATATYPE.add(Datatypes.u8, "structsize", "Size of this structure");
			DATATYPE.add(Datatypes.makeArray(Datatypes.u8, 1), "reserved1", "");
			DATATYPE.add(Datatypes.u16, "version", "Library version");
			DATATYPE.add(libraryAttributesType, "attribute", "Library attributes");
			DATATYPE.add(Datatypes.u16, "nfunc", "Number of functions imported from this library");
			DATATYPE.add(Datatypes.u16, "nvar", "Number of variables imported from this library");
			DATATYPE.add(Datatypes.u16, "ntlsvar", "Number of TLS variables imported from this library");
			DATATYPE.add(Datatypes.u32, "libname_nid", "NID corresponding to library name");
			DATATYPE.add(Datatypes.stringptr, "libname", "Pointer to library's name");
			DATATYPE.add(Datatypes.u32ptr, "func_nidtable", "Pointer to functions NID table");
			DATATYPE.add(Datatypes.ptr_to_ptr, "func_table", "Pointer to functions table");
			DATATYPE.add(Datatypes.u32ptr, "var_nidtable", "Pointer to variables NID table");
			DATATYPE.add(Datatypes.ptr_to_ptr, "var_table", "Pointer to variables table");

			Utils.assertStructureSize(DATATYPE, SIZE);
		}
		return DATATYPE;
	}
	private StructureDataType DATATYPE;
}
