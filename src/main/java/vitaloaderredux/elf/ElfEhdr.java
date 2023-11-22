package vitaloaderredux.elf;

import java.io.IOException;
import java.io.RandomAccessFile;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.Writeable;
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfProgramHeaderConstants;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.util.DataConverter;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.exception.DuplicateNameException;
import vitaloaderredux.misc.Datatypes;

public class ElfEhdr implements StructConverter, Writeable {
	
	//For e_type
	static private final int ETSCEEXEC = 0xFE00, 
		ETSCERELEXEC = 0xFE04, ETSCEARMRELEXEC = 0xFFA5;
	
	static private final int EHDR_SIZE = 52, PHDR_SIZE = 0x20, SHDR_SIZE = 0x28;
	
	static public final short EM_CYGNUS_MEP = (short)0xF00D;
	
	public enum ElfType implements StructConverter {
		ET_REL, ET_EXEC, ET_CORE,
		ET_SCE_EXEC, ET_SCE_RELEXEC, ET_SCE_ARMRELEXEC;

		static public ElfType fromInteger(int itype) {
			itype &= 0xFFFF;
			if (itype == ElfConstants.ET_REL)  return ET_REL;
			if (itype == ElfConstants.ET_EXEC) return ET_EXEC;
			if (itype == ElfConstants.ET_CORE) return ET_CORE;
			if (itype == ETSCEEXEC) return ET_SCE_EXEC;
			if (itype == ETSCERELEXEC) return ET_SCE_RELEXEC;
			if (itype == ETSCEARMRELEXEC) return ET_SCE_ARMRELEXEC;
			throw new IllegalArgumentException("Unreachable");
		}
				
		public String description() {
			switch (this) {
			case ET_REL: return "Relocatable executable";
			case ET_EXEC: return "Fixed executable";
			case ET_CORE: return "Core file";
			case ET_SCE_EXEC: return "SCE Executable";
			case ET_SCE_RELEXEC: return "SCE Relocatable Executable";
			case ET_SCE_ARMRELEXEC: return "ARM Relocatable Executable";
			default: throw new IllegalArgumentException("Unreachable");
			}
		}

		public boolean relocatable() {
			return 	(this == ET_REL) ||
					(this == ET_SCE_RELEXEC) ||
					(this == ET_SCE_ARMRELEXEC);
		}
		
		static public DataType getDataType() {
			if (ELFTYPE_ENUM == null) {
				ELFTYPE_ENUM = new EnumDataType(Datatypes.ELF_CATPATH, "Elf32_EType", UnsignedShortDataType.dataType.getLength());
				ELFTYPE_ENUM.add("ET_REL", ElfConstants.ET_REL);
				ELFTYPE_ENUM.add("ET_EXEC", ElfConstants.ET_EXEC);
				ELFTYPE_ENUM.add("ET_CORE", ElfConstants.ET_CORE);
				ELFTYPE_ENUM.add("ET_SCE_EXEC", ETSCEEXEC);
				ELFTYPE_ENUM.add("ET_SCE_RELEXEC", ETSCERELEXEC);
				ELFTYPE_ENUM.add("ET_SCE_ARMRELEXEC", ETSCEARMRELEXEC);
			}
			return ELFTYPE_ENUM;
		}
		static EnumDataType ELFTYPE_ENUM = null;
		
		@Override
		public DataType toDataType() throws DuplicateNameException, IOException {
			return getDataType();
		}
	}
	
	private static EnumDataType e_machine_enum = null;
	private static DataType GetEMachineDataType() {
		if (e_machine_enum == null) {
			e_machine_enum = new EnumDataType(Datatypes.ELF_CATPATH, "Elf32_EMachine", 2);
			e_machine_enum.add("EM_ARM", ElfConstants.EM_ARM);
			e_machine_enum.add("EM_CYGNUS_MEP", EM_CYGNUS_MEP);
		}
		return e_machine_enum;
	}
	
	public final byte ei_osabi;
	public final byte ei_abiversion;
	public final byte ei_pad[];
	
	public final short e_machine;
	
	public final short e_type;
	public final ElfType execType;
	public final long e_entry;
	public final long e_phoff;
	public final long e_shoff;
	public final long e_flags;
//	public final int e_ehsize;
//	public final int e_phentsize;
	public final int e_phnum;
	public final int e_shentsize;
	public final int e_shnum;
	public final int e_shstrndx;
	
	public ElfPhdr[] programHeaders = null;
	public ElfShdr[] sectionHeaders = null;
	
	public final ByteProvider byteProvider;
	
	/**
	 * 
	 * @param provider
	 * @throws IOException when a BinaryReader error occurs.
	 * @throws IllegalArgumentException when the ELF header is invalid.
	 */
	public ElfEhdr(ByteProvider provider) throws IOException {
		byteProvider = provider;
		BinaryReader reader = new BinaryReader(byteProvider, true);
	
		byte magic0 = reader.readNextByte();
		String magic123 = reader.readNextAsciiString(ElfConstants.MAGIC_STR_LEN);
		if (magic0 != ElfConstants.MAGIC_NUM || !magic123.equals(ElfConstants.MAGIC_STR))
		{
			throw new MalformedElfException("No ELF magic");
		}
		
		final byte ei_class = reader.readNextByte();
		if (ei_class != ElfConstants.ELF_CLASS_32) {
			throw new UnsupportedElfException("Unexpected EI_CLASS");
		}
		
		final byte ei_data = reader.readNextByte();
		if (ei_data != ElfConstants.ELF_DATA_LE) {
			throw new UnsupportedElfException("Unexpected EI_DATA");
		}
		
		final byte ei_version = reader.readNextByte();
		if (ei_version != ElfConstants.EV_CURRENT) {
			throw new UnsupportedElfException("Unexpected EI_VERSION");
		}
		
		ei_osabi = reader.readNextByte();
		ei_abiversion = reader.readNextByte();
		ei_pad = reader.readNextByteArray(7);
		
		e_type = reader.readNextShort();
		execType = ElfType.fromInteger(e_type);

		e_machine = reader.readNextShort();
		if (e_machine != ElfConstants.EM_ARM && e_machine != EM_CYGNUS_MEP) {
			throw new UnsupportedElfException("Unexpected e_machine");
		}
		
		long e_version = reader.readNextUnsignedInt();
		if (e_version != ElfConstants.EV_CURRENT) {
			throw new UnsupportedElfException("Unexpected e_version");
		}
		
		e_entry = reader.readNextUnsignedInt();
		
		e_phoff = reader.readNextUnsignedInt();
		if (e_phoff > provider.length()) {
			throw new MalformedElfException("e_phoff " + e_phoff + " is too big (max = " + provider.length() + ")"); 
		}
		
		e_shoff = reader.readNextUnsignedInt();
		if (e_shoff > provider.length()) {
			throw new MalformedElfException("e_shoff " + e_shoff + " is too big (max = " + provider.length() + ")");
		}
		
		e_flags = reader.readNextUnsignedInt();
		
		int e_ehsize = reader.readNextUnsignedShort();
		if (e_ehsize != EHDR_SIZE) {
			throw new UnsupportedElfException("Unexpected e_ehsize " + e_ehsize);
		}
		
		int e_phentsize = reader.readNextUnsignedShort();
		if (e_phentsize != PHDR_SIZE) {
			throw new UnsupportedElfException("Unexpected e_phentsize " + e_phentsize);
		}
		
		e_phnum = reader.readNextUnsignedShort();
		
		e_shentsize = reader.readNextUnsignedShort();
		if (e_shentsize != 0 && e_shentsize != SHDR_SIZE) { //e_shentsize is 0 when sections are stripped
			throw new UnsupportedElfException("Unexpected e_shentsize " + e_shentsize);
		}
		
		e_shnum = reader.readNextUnsignedShort();
		e_shstrndx = reader.readNextUnsignedShort();
		if (e_shnum > 0 && e_shstrndx >= e_shnum) {
			throw new MalformedElfException(String.format("e_shstrndx (%d) >= e_shnum (%d)", e_shstrndx, e_shnum));
		}
		
		parseProgramHeaders();
		
		try {
			parseSegmentHeaders();
			parseSegmentNames();
		} catch (IOException e) {
			//Silently swallow... sections aren't very important.
		}
	}
	
	public int getImageBase() {
		if (e_phnum == 0) {
			return 0;
		}
		
		//Must use long to ensure comparisions work as expected.
		long base = 0x81000000;
		
		//Find smallest p_vaddr
		for (ElfPhdr Phdr: programHeaders) {
			if (Phdr.p_type == ElfProgramHeaderConstants.PT_LOAD && Phdr.p_vaddr < base) {
				base = Phdr.p_vaddr;
			}
		}
		return (int)(base & 0xFFFFFFFFl);
	}
	
	public class ModInfoLocation {
		public final int segmentIndex;
		public final int segmentOffset;
		public final int fileOffset;
		
		public ModInfoLocation(int segmentIdx, int segmentFileOffset, int offsetInSegment) {
			segmentIndex = segmentIdx;
			segmentOffset = offsetInSegment;
			fileOffset = segmentFileOffset + offsetInSegment;
		}
	}
	
	//This method is only valid for ARM ELF.
	public ModInfoLocation getModuleInfoLocation() throws MalformedElfException, UnsupportedElfException {
		if (e_machine != ElfConstants.EM_ARM) {
			throw new UnsupportedElfException("Only ARM ELFs have a SceModuleInfo");
		}
		
		//If the ELF has sections, try to find .sceModuleInfo.rodata
		
		//TODO: is this correct?
		//TODO: find segment metadata by section
		/*
		if (e_shnum > 0) {
			for (ElfShdr sHdr: sectionHeaders) {
				if (sHdr.name.equals(".sceModuleInfo.rodata")) {
					return null;
				}
			}
		}
		*/
		
		//Legacy ELF format (Prx1): module info FILE offset is stored in first segment's p_paddr.
		if (isPrx1ELF()) {
			ElfPhdr Phdr = programHeaders[0];
			int modInfoOffset = (int)(Phdr.p_paddr - Phdr.p_offset);
			if (modInfoOffset < 0) {
				throw new MalformedElfException("Prx1 ELF: bad SceModuleInfo offset");
			}
			
			return new ModInfoLocation(0, (int)Phdr.p_offset, modInfoOffset);
		}
		
		//How does Modulemgr find the SceModuleInfo? Why reinvent the wheel?
		//
		//Answer: in 4.00, the following method is always used:
		//	SceModuleInfo segment:offset = (e_entry<31:30>:e_entry<29:0>)
		//
		//However, 4.00 only supports infoversion 6...
		//
		//RE of older firmwares is required, but alas, I think
		//we'll have to resort to hacks to have universal support.
		
		//For some ET_SCE_EXEC, module info offset is stored in the segment's p_paddr.
		//TODO: is this true?!
		for (int i = 0; i < e_phnum; i++) {
			ElfPhdr Phdr = programHeaders[i];
			//Check paddr is non-NULL and is a valid offset
			if (Phdr.p_paddr != 0 && (Phdr.p_paddr < Phdr.p_filesz)) {
				//TODO: is this correct?
				return new ModInfoLocation(i, (int)Phdr.p_offset, (int)Phdr.p_paddr);
			}
		}
		

		//For ET_SCE_RELEXEC and some ET_SCE_EXEC, the Ehdr's e_entry stores the segment:offset to the SceModuleInfo.
		//Top two bits = segment index, bottom 30 bits = offset in segment.
		byte segNdx = (byte)((e_entry >> 30) & 0x3);
		int segOffset = (int)(e_entry & 0x3FFFFFFF);
		
		if (segNdx > e_phnum) {
			throw new MalformedElfException(String.format("segNdx (%d) > e_phnum (%d)", segNdx, e_phnum));
		}
		
		ElfPhdr segHdr = programHeaders[segNdx];
		if (segHdr.p_type != ElfProgramHeaderConstants.PT_LOAD) {
			throw new MalformedElfException(String.format("Illegal segment type 0x%X for SceModuleInfo", segHdr.p_type));
		}
		
		if (segOffset > segHdr.p_filesz) {
			throw new MalformedElfException(String.format("segOffset (%d) > seg.p_filesz (%d)", segOffset, segHdr.p_filesz));
		}
		
		//TODO: is this correct?
		return new ModInfoLocation(segNdx, (int)segHdr.p_offset, segOffset);
	}
	
	/**
	 * Get the offset in file of the SceModuleInfo structure.
	 * @return File offset of SceModuleInfo, or -1 if not found
	 * @throws UnsupportedElfException 
	 * @throws MalformedElfException 
	 */
	public long getModuleInfoFileOffset() throws MalformedElfException, UnsupportedElfException {
		ModInfoLocation loc = getModuleInfoLocation();
		return loc.fileOffset;
	}
	
	private BinaryReader makeReaderForOffset(long offset) {
		return new BinaryReader(byteProvider, LittleEndianDataConverter.INSTANCE, offset);
	}
	
	private void parseProgramHeaders() throws IOException {
		if (e_phnum > 0) {
			programHeaders = new ElfPhdr[e_phnum];
			for (int i = 0; i < e_phnum; i++) {
				BinaryReader hdrReader = makeReaderForOffset(e_phoff + i * PHDR_SIZE);
				programHeaders[i] = new ElfPhdr(hdrReader);
			}
		}
	}
	
	private void parseSegmentHeaders() throws IOException {
		if (e_shnum > 0) {
			sectionHeaders = new ElfShdr[e_shnum];
			for (int i = 0; i < e_shnum; i++) {
				BinaryReader hdrReader = makeReaderForOffset(e_shoff + i * e_shentsize);
				sectionHeaders[i] = new ElfShdr(hdrReader);
			}
		}
	}

	private void parseSegmentNames() throws IOException {
		if (e_shnum <= 0)
			return;
		
		if (e_shstrndx >= 0) {
			ElfShdr namesSection = sectionHeaders[e_shstrndx];
			BinaryReader namesReader = makeReaderForOffset(namesSection.sh_offset);
				
			for (int i = 0; i < e_shnum; i++) {
				ElfShdr section = sectionHeaders[i];
				String name = namesReader.readAsciiString(section.sh_name);
				if (!name.equals("")) {
					section.name = name;
				} else {
					section.name = String.format("SECTION_%d", i);
				}
			}
		} else {
			for (int i = 0; i < e_shnum; i++) {
					sectionHeaders[i].name = String.format("SECTION_%d", i);
			}
		}
		
	}

	public static DataType getDataType() {
		DataType e_typeDatatype = ElfType.getDataType();
		DataType u8 = ByteDataType.dataType;
		DataType u16 = UnsignedShortDataType.dataType;
		DataType u32 = UnsignedIntegerDataType.dataType;
		DataType char8 = CharDataType.dataType;
		
		StructureDataType dt = new StructureDataType(Datatypes.ELF_CATPATH, "Elf32_Ehdr", 0);
		dt.add(u8, "ei_magic", "0x7F");
		dt.add(new ArrayDataType(char8, 3, char8.getLength()), "ei_magic_str", "ELF");
		dt.add(u8, "ei_class", "Bitness class");
		dt.add(u8, "ei_data", "Data ordering");
		dt.add(u8, "ei_version", "ELF version");
		dt.add(u8, "ei_osabi", "OS ABI");
		dt.add(u8, "ei_abiversion", "ABI Version");
		dt.add(new ArrayDataType(u8, 7, u8.getLength()), "ei_pad", "Padding");
		dt.add(e_typeDatatype, "e_type", "ELF file type");
		dt.add(GetEMachineDataType(), "e_machine", "ELF target machine");
		dt.add(u32, "e_version", "ELF Ehdr version");
		dt.add(u32, "e_entry", "Entrypoint");
		dt.add(u32, "e_phoff", "Offset to Program headers");
		dt.add(u32, "e_shoff", "Offset to Section headers");
		dt.add(u32, "e_flags", null);
		dt.add(u16, "e_ehsize", "Size of ELF header");
		dt.add(u16, "e_phentsize", "Size of program header");
		dt.add(u16, "e_phnum", "Number of program headers");
		dt.add(u16, "e_shentsize", "Size of section header");
		dt.add(u16, "e_shnum", "Number of section headers");
		dt.add(u16, "e_shstrndx", "Index of string section");
		return dt;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return getDataType();
	}
	
	@Override
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException {
		raf.write((byte)0x7F);
		raf.write((byte)'E');
		raf.write((byte)'L');
		raf.write((byte)'F');
		raf.write(ElfConstants.ELF_CLASS_32);
		raf.write(ElfConstants.ELF_DATA_LE);
		raf.write(ElfConstants.EV_CURRENT);
		raf.write(ei_osabi);
		raf.write(ei_abiversion);
		raf.write(ei_pad);
		
		DataConverter LEDC = LittleEndianDataConverter.INSTANCE;
		
		//Multi-byte fields must be converted to be written in little endian
		raf.write(LEDC.getBytes(e_type));
		raf.write(LEDC.getBytes(e_machine));
		raf.write(LEDC.getBytes((int)ElfConstants.EV_CURRENT));
		raf.write(LEDC.getBytes((int)e_entry));
		raf.write(LEDC.getBytes((int)e_phoff));
		raf.write(LEDC.getBytes((int)e_shoff));
		raf.write(LEDC.getBytes((int)e_flags));
		raf.write(LEDC.getBytes((short)EHDR_SIZE));
		raf.write(LEDC.getBytes((short)PHDR_SIZE));
		raf.write(LEDC.getBytes((short)e_phnum));
		raf.write(LEDC.getBytes((short)e_shentsize));
		raf.write(LEDC.getBytes((short)e_shnum));
		raf.write(LEDC.getBytes((short)e_shstrndx));
	}
	
	public boolean isPrx1ELF() {
		if (e_type == (short)ETSCEARMRELEXEC)
			return true;
		
		if (e_type == ElfConstants.ET_EXEC)
			return true;
		
		if (e_type == ElfConstants.ET_REL)
			return true;
		
		//Either ET_SCE_EXEC, ET_SCE_RELEXEC or ET_CORE (which are generated by faps-coredump)
		return false;
	}
}
