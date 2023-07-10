package vitaloaderredux.scetypes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IBO32DataType;
import ghidra.program.model.data.StructureDataType;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.elf.UnsupportedElfException;
import vitaloaderredux.misc.Datatypes;

/**
 * 
 * @author CreepNT
 *
 *
 * @note For this structure, fields marked "RVA" hold offsets 
 * in the current segment(?) instead of true virtual addresses.
 */
public class SceModuleInfo {
	public static final String STRUCTURE_NAME = "SceModuleInfo";
	
	public final short attributes;
	public final short[] version = { 0, 0 };
	public final String modname;
	public final byte infover;
	public final long gp_value;
	public final long libent_top;  //RVA
	public final long libent_btm;  //RVA - libents are in [libent_top; libent_btm)
	public final long libstub_top; //RVA
	public final long libstub_btm; //RVA - libstubs are in [libstub_top; libstub_btm)
	public final long fingerprint;
	
	//Those fields can't be marked as final because they may be left uninitialized...
	public long start_entry; //RVA - 0xFFFFFFFF if not present!
	public long stop_entry;  //RVA - 0xFFFFFFFF if not present!
	
	public long tls_top; //RVA - 0 if not present
	public long tls_filesz;
	public long tls_memsz;

	public long exidx_top; //RVA
	public long exidx_btm; //RVA
	public long extab_top; //RVA
	public long extab_btm; //RVA

	//strict = false: only check the module name is NUL-terminated
	//strict = true : check that all characters in the modules name are valid ASCII or NUL
	public static boolean verifyModuleInfoName(BinaryReader nameReader, boolean strict) throws IOException {
		byte[] rawName = nameReader.readByteArray(nameReader.getPointerIndex(), 27);
		int nulCharIndex = -1;		
		
		for (int i = 0; i < rawName.length; i++) {
			byte b = rawName[i];
			if (b == '\0') {
				nulCharIndex = i;
				if (!strict) {
					break;
				}
			}
			
			if (strict && b != '\0' && !(0x20 <= b && b <= 0x7E)) {
				return false;
			}
		}
		return (nulCharIndex == -1) ? false : true;
	}
	
	private void assertValidName(BinaryReader r) throws IOException {
		if (!verifyModuleInfoName(r, false)) {
			throw new MalformedElfException("Malformed SceModuleInfo (bad name)");
		}
	}
	
	private StructureDataType STRUCTURE = null;	
	public SceModuleInfo(BinaryReader reader) throws IOException {
		attributes = reader.readNextShort();
		version[0] = reader.readNextByte();
		version[1] = reader.readNextByte();
		
		assertValidName(reader);

		modname = reader.readNextAsciiString(27);
		
		infover = reader.readNextByte();

		//Fields common to all versions
		gp_value = reader.readNextUnsignedInt();
		libent_top = reader.readNextUnsignedInt();
		libent_btm = reader.readNextUnsignedInt();
		libstub_top = reader.readNextUnsignedInt();
		libstub_btm = reader.readNextUnsignedInt();
		
		if (infover == 0) {
			throw new UnsupportedElfException("SceModuleInfo with infover 0");
		}
		
		fingerprint = reader.readNextUnsignedInt();
		
		//Change according to version
		if (infover < 6) {
			if (infover >= 1) { //v1 fields
				start_entry = reader.readNextUnsignedInt();
				stop_entry = reader.readNextUnsignedInt();
			}
			
			if (infover >= 2) { //v2 fields
				exidx_top = reader.readNextUnsignedInt();
				exidx_btm = reader.readNextUnsignedInt();
			}
			
			if (infover == 3) { //v3 fields
				tls_top = reader.readNextUnsignedInt();
				tls_filesz = reader.readNextUnsignedInt();
				tls_memsz = reader.readNextUnsignedInt();
			}

			if (infover > 3) {
				throw new UnsupportedElfException("SceModuleInfo with infover 4/5 is not supported!");
			}
		} else {
			if (infover > 6) {
				throw new UnsupportedElfException("SceModuleInfo with infover > 6 is not supported!");
			}
			
			tls_top = reader.readNextUnsignedInt();
			tls_filesz = reader.readNextUnsignedInt();
			tls_memsz = reader.readNextUnsignedInt();
			start_entry = reader.readNextUnsignedInt();
			stop_entry = reader.readNextUnsignedInt();
			exidx_top = reader.readNextUnsignedInt();
			exidx_btm = reader.readNextUnsignedInt();
			extab_top = reader.readNextUnsignedInt();
			extab_btm = reader.readNextUnsignedInt();
		}
	}
	
	public DataType toDataType(DataType moduleAttributesDataType) {		
		if (STRUCTURE == null) {
			//Not the correct type ! But it's as good as we can do...
			//Maybe we shouldn't use it to not break analysis though :shrug:
			final DataType IBO32 = IBO32DataType.dataType;
			
			STRUCTURE = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, STRUCTURE_NAME, 0);
			STRUCTURE.add(moduleAttributesDataType, "modattr", "Module attributes");
			STRUCTURE.add(Datatypes.makeArray(Datatypes.u8, 2), "modver", "Module version ([0] = major, [1] = minor)");
			STRUCTURE.add(Datatypes.makeArray(Datatypes.char8, 27), "modname", "Module name");
			STRUCTURE.add(Datatypes.u8, "infover", "SceModuleInfo version");
			STRUCTURE.add(Datatypes.u32, "gp_value", "gp register value (unused on Vita)");
			STRUCTURE.add(IBO32, "libent_top", "Address of exports table top");
			STRUCTURE.add(IBO32, "libent_end", "Address of exports table bottom");
			STRUCTURE.add(IBO32, "libstub_top", "Address of imports table top");
			STRUCTURE.add(IBO32, "libstub_end", "Address of imports table bottom");
			STRUCTURE.add(Datatypes.u32, "fingerprint", "Module fingerprint");
			
			
			
			//Change according to version
			if (infover < 6) {
				if (infover >= 1) { //v1 fields
					STRUCTURE.add(IBO32, "start_entry", "Address of the module_start entrypoint");
					STRUCTURE.add(IBO32, "stop_entry", "Address of the module_stop entrypoint");
				}
				
				if (infover >= 2) { //v2 fields
					STRUCTURE.add(IBO32, "exidx_top", "ARM EABI exception index table top");
					STRUCTURE.add(IBO32, "exidx_btm", "ARM EABI exception index table bottom");
				}
				
				if (infover == 3) { //v3 fields
					STRUCTURE.add(IBO32, "tls_start", "Address of TLS section start");
					STRUCTURE.add(Datatypes.u32, "tls_file_size", "Size of the TLS section in file");
					STRUCTURE.add(Datatypes.u32, "tls_mem_size", "Size of the TLS section in memory");
				}
			} else {
				STRUCTURE.add(IBO32, "tls_top", "TLS top");
				STRUCTURE.add(Datatypes.u32, "tls_file_size", "Size of the TLS section in file");
				STRUCTURE.add(Datatypes.u32, "tls_mem_size", "Size of the TLS section in memory");
				STRUCTURE.add(IBO32, "start_entry", "Address of the module_start entrypoint");
				STRUCTURE.add(IBO32, "stop_entry", "Address of the module_stop entrypoint");
				STRUCTURE.add(IBO32, "exidx_top", "ARM EABI exception index table top");
				STRUCTURE.add(IBO32, "exidx_btm", "ARM EABI exception index table bottom");
				STRUCTURE.add(IBO32, "extab_start", "ARM EABI exception table top");
				STRUCTURE.add(IBO32, "extab_end", "ARM EABI exception table bottom");
			}
		}
		
		return STRUCTURE;
	}
}
