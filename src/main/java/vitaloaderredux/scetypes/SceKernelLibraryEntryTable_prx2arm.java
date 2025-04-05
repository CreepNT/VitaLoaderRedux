package vitaloaderredux.scetypes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;

//Used in PRX2 format ELFs
public class SceKernelLibraryEntryTable_prx2arm extends ILibent {
	public static final String STRUCTURE_NAME = "sceKernelLibraryEntryTable_prx2arm";
	public static final int SIZE = 0x20;

	@Override
	protected String _structureName() { return STRUCTURE_NAME; }

	public SceKernelLibraryEntryTable_prx2arm(BinaryReader reader) throws IOException {
		final int structureSize = reader.readNextByte();
		if (structureSize != SIZE) {
			throw new MalformedElfException(String.format("Invalid Libent size! (0x%X != 0x%X)", structureSize, SIZE));
		}

		auxattribute = reader.readNextByte();
		version = reader.readNextUnsignedShort();
		attribute = reader.readNextUnsignedShort();
		nfunc = reader.readNextUnsignedShort();
		nvar = reader.readNextUnsignedShort();
		ntlsvar = reader.readNextUnsignedShort();
		hashinfo = reader.readNextByte();
		hashinfotls = reader.readNextByte();
		reader.readNextByte(); //reserved2
		nidaltsets = reader.readNextByte();

		libname_nid = reader.readNextInt();
		libname = reader.readNextInt();

		nidtable = reader.readNextInt();
		addtable = reader.readNextInt();

		Utils.assertBRSize(STRUCTURE_NAME, reader, SIZE);
	}

	@Override
	public DataType toDataType(DataType libraryAttributesType) {
		if (DATATYPE == null) {
			DATATYPE = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
			DATATYPE.add(_getCommonDataType(libraryAttributesType, false), "c", "");
			DATATYPE.add(Datatypes.u32, "libname_nid", "NID corresponding to library name");
			DATATYPE.add(Datatypes.stringptr, "libname", "Pointer to library's name");
			DATATYPE.add(Datatypes.u32ptr, "nidtable", "Pointer to library's NID table");
			DATATYPE.add(Datatypes.ptr_to_ptr, "addtable", "Pointer to library's address table");

			Utils.assertStructureSize(DATATYPE, SIZE);
		}
		return DATATYPE;
	}
	private StructureDataType DATATYPE;
}
