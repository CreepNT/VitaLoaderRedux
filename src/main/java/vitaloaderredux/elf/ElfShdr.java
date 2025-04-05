package vitaloaderredux.elf;


import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.elf.ElfSectionHeaderConstants;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import vitaloaderredux.misc.Datatypes;

public class ElfShdr {
	static public final CategoryPath ELF_CATPATH = Datatypes.ELF_CATPATH;

	/**
	 * @return DataType for the sh_type field
	 */
	static public DataType getShdrTypeDataType() {
		EnumDataType dt = new EnumDataType(ELF_CATPATH, "Elf32_ShdrType", 4);
		dt.add("SHT_NULL", ElfSectionHeaderConstants.SHT_NULL, "Unused entry");
		dt.add("SHT_PROGBITS", ElfSectionHeaderConstants.SHT_PROGBITS, "Program data");
		dt.add("SHT_SYMTAB", ElfSectionHeaderConstants.SHT_SYMTAB, "Symbol table");
		dt.add("SHT_STRTAB", ElfSectionHeaderConstants.SHT_STRTAB, "String table");
		dt.add("SHT_RELA", ElfSectionHeaderConstants.SHT_RELA, "Relocation entries with addends");
		dt.add("SHT_HASH", ElfSectionHeaderConstants.SHT_HASH, "Symbol hash table");
		dt.add("SHT_DYNAMIC", ElfSectionHeaderConstants.SHT_DYNAMIC, "Dynamic linking information");
		dt.add("SHT_NOTE", ElfSectionHeaderConstants.SHT_NOTE, "Notes");
		dt.add("SHT_NOBITS", ElfSectionHeaderConstants.SHT_NOBITS, "Program space with no data (bss)");
		dt.add("SHT_REL", ElfSectionHeaderConstants.SHT_REL, "Relocation entries, no addends");
		dt.add("SHT_SHLIB", ElfSectionHeaderConstants.SHT_SHLIB, "Reserved");
		dt.add("SHT_DYNSYM", ElfSectionHeaderConstants.SHT_DYNSYM, "Dynamic linker symbol table");
		dt.add("SHT_INIT_ARRAY", ElfSectionHeaderConstants.SHT_INIT_ARRAY, "Array of constructors");
		dt.add("SHT_FINI_ARRAY", ElfSectionHeaderConstants.SHT_FINI_ARRAY, "Array of destructors");
		dt.add("SHT_PREINIT_ARRAY", ElfSectionHeaderConstants.SHT_PREINIT_ARRAY, "Array of pre-constructors");
		dt.add("SHT_GROUP", ElfSectionHeaderConstants.SHT_GROUP, "Section group");
		dt.add("SHT_SYMTAB_SHNDX", ElfSectionHeaderConstants.SHT_SYMTAB_SHNDX, "Extended section indices");
		//TODO: add SCE section header types
		return dt;
	}

	/**
	 * @return DataType for the sh_flags field
	 */
	static public DataType getShdrFlagsDataType() {
		EnumDataType dt = new EnumDataType(Datatypes.ELF_CATPATH, "Elf32_ShdrFlags", 4);
		dt.add("SHF_WRITE", ElfSectionHeaderConstants.SHF_WRITE, "Writable section");
		dt.add("SHF_ALLOC", ElfSectionHeaderConstants.SHF_ALLOC, "Section occupies memory during execution");
		dt.add("SHF_EXECINSTR", ElfSectionHeaderConstants.SHF_EXECINSTR, "Executable section");

		dt.add("SHF_MERGE", ElfSectionHeaderConstants.SHF_MERGE, "Section might be merged");
		dt.add("SHF_STRINGS", ElfSectionHeaderConstants.SHF_STRINGS, "Section contains NUL-terminated strings");
		dt.add("SHF_INFO_LINK", ElfSectionHeaderConstants.SHF_INFO_LINK, "sh_info holds an SHT index");
		dt.add("SHF_LINK_ORDER", ElfSectionHeaderConstants.SHF_LINK_ORDER, "Section order must be preserved after combining");
		dt.add("SHF_OS_NONCONFORMING", ElfSectionHeaderConstants.SHF_OS_NONCONFORMING, "OS-specific handling is required");
		dt.add("SHF_GROUP", ElfSectionHeaderConstants.SHF_GROUP, "Section is member of a group");
		dt.add("SHF_TLS", ElfSectionHeaderConstants.SHF_TLS, "Sections holds thread-local data");
		dt.add("SHF_COMPRESSED", ElfSectionHeaderConstants.SHF_COMPRESSED, "Section is compressed");
		return dt;
	}

	static public DataType getDataType() {
		if (SHDR_DATATYPE == null) {
			DataType uint = UnsignedIntegerDataType.dataType;

			//TODO: make sh_flags a EnumDataType as well
			SHDR_DATATYPE = new StructureDataType(ELF_CATPATH, "Elf32_Shdr", 0);
			SHDR_DATATYPE.add(uint, "sh_name", "");
			SHDR_DATATYPE.add(getShdrTypeDataType(), "sh_type", "");
			SHDR_DATATYPE.add(getShdrFlagsDataType(), "sh_flags", "");
			SHDR_DATATYPE.add(uint, "sh_addr", "");
			SHDR_DATATYPE.add(uint, "sh_offset", "");
			SHDR_DATATYPE.add(uint, "sh_size", "");
			SHDR_DATATYPE.add(uint, "sh_link", "");
			SHDR_DATATYPE.add(uint, "sh_info", "");
			SHDR_DATATYPE.add(uint, "sh_addralign", "");
			SHDR_DATATYPE.add(uint, "sh_entsize", "");
		}
		return SHDR_DATATYPE;
	}
	static StructureDataType SHDR_DATATYPE = null;

	public final long sh_name;   //offset to name in .shstrtab section
	public final long sh_type;   //section type
	public final long sh_flags;  //section attributes
	public final long sh_addr;   //section virtual address
	public final long sh_offset; //section file offset
	public final long sh_size;   //section size in file
	public final long sh_link;
	public final long sh_info;
	public final long sh_addralign;
	public final long sh_entsize;

	//Section name. Must be filled up by class user.
	public String name = null;

	//User data. Can be used by class user to store an object associated to the section.
	public Object userData;

	public ElfShdr(BinaryReader reader) throws IOException {
		sh_name = reader.readNextUnsignedInt();
		sh_type = reader.readNextUnsignedInt();
		sh_flags = reader.readNextUnsignedInt();
		sh_addr = reader.readNextUnsignedInt();
		sh_offset = reader.readNextUnsignedInt();
		sh_size = reader.readNextUnsignedInt();
		sh_link = reader.readNextUnsignedInt();
		sh_info = reader.readNextUnsignedInt();
		sh_addralign = reader.readNextUnsignedInt();
		sh_entsize = reader.readNextUnsignedInt();
	}
}