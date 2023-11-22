package vitaloaderredux.elf;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.elf.ElfProgramHeaderConstants;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import vitaloaderredux.misc.Datatypes;

public class ElfPhdr {
	//TODO: verify only those exist
	static public final int PT_SCE_RELA    = 0x60000000;
	static public final int PT_SCE_COMMENT = 0x6FFFFF00;
	static public final int PT_SCE_VERSION = 0x6FFFFF01;
	static public final int PT_ARM_UNWIND  = 0x70000001; //Also called PT_ARM_EXIDX
	static public final int PT_SCE_ARMRELA = 0x700000A4; //Used for relocations in PRX1 format

	//Present on .data relocation segment, absent on .text relocation segment.
	static public final int PF_DATA_RELA = 0x10000;
	
	/**
	 * @return DataType for the p_type field
	 */
	static public DataType getPhdrTypeDataType() {
		EnumDataType dt = new EnumDataType(Datatypes.ELF_CATPATH, "Elf32_PhdrType", 4);
		dt.add("PT_NULL", ElfProgramHeaderConstants.PT_NULL);
		dt.add("PT_LOAD", ElfProgramHeaderConstants.PT_LOAD);
		dt.add("PT_NOTE", ElfProgramHeaderConstants.PT_NOTE);
		dt.add("PT_SCE_RELA", PT_SCE_RELA, "Relocation segment");
		dt.add("PT_SCE_COMMENT", PT_SCE_COMMENT);
		dt.add("PT_SCE_VERSION", PT_SCE_VERSION);
		dt.add("PT_ARM_UNWIND", PT_ARM_UNWIND, "Exception unwind tables segment");
		dt.add("PT_SCE_ARMRELA", PT_SCE_ARMRELA, "PRX1 relocation segment");
		return dt;
	}
	
	/**
	 * @return DataType for the p_flags field
	 */
	static public DataType getPhdrFlagsDataType() {
		EnumDataType dt = new EnumDataType(Datatypes.ELF_CATPATH, "Elf32_PhdrFlags", 4);
		dt.add("PF_X", 1);
		dt.add("PF_W", 2);
		dt.add("PF_R", 4);
		return dt;
	}
	
	static public DataType getDataType() {
		if (PHDR_DATATYPE == null) {
			DataType uint = UnsignedIntegerDataType.dataType;
			
			//TODO: make p_flags a EnumDataType as well
			PHDR_DATATYPE = new StructureDataType(Datatypes.ELF_CATPATH, "Elf32_Phdr", 0);
			PHDR_DATATYPE.add(getPhdrTypeDataType(), "p_type", "");
			PHDR_DATATYPE.add(uint, "p_offset", "");
			PHDR_DATATYPE.add(uint, "p_vaddr", "");
			PHDR_DATATYPE.add(uint, "p_vaddr", "");
			PHDR_DATATYPE.add(uint, "p_filesz", "");
			PHDR_DATATYPE.add(uint, "p_memsz", "");
			PHDR_DATATYPE.add(getPhdrFlagsDataType(), "p_flags", "");
			PHDR_DATATYPE.add(uint, "p_align", "");
		}
		return PHDR_DATATYPE;
	}
	static StructureDataType PHDR_DATATYPE = null;
	
	public final long p_type;
	public final long p_offset;
	public final long p_vaddr;
	public final long p_paddr;
	public final long p_filesz;
	public final long p_memsz;
	public final long p_flags;
	public final long p_align;
	
	//User data. Can be used to store an object associated to the segment.
	public Object userData;
	
	public ElfPhdr(BinaryReader reader) throws IOException {
		p_type = reader.readNextUnsignedInt();
		p_offset = reader.readNextUnsignedInt();
		p_vaddr = reader.readNextUnsignedInt();
		p_paddr = reader.readNextUnsignedInt();
		p_filesz = reader.readNextUnsignedInt();
		p_memsz = reader.readNextUnsignedInt();
		p_flags = reader.readNextUnsignedInt();
		p_align = reader.readNextUnsignedInt();
	}
}
