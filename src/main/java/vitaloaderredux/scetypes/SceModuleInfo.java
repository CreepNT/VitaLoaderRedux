package vitaloaderredux.scetypes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IBO32DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import vitaloaderredux.elf.MalformedElfException;
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
	public final long resreve;	   //Reserved.
	public final long ent_top;  //RVA
	public final long ent_end;  //RVA - libents are in [libent_top; libent_btm)
	public final long stub_top; //RVA
	public final long stub_end; //RVA - libstubs are in [libstub_top; libstub_btm)
	public final long dbg_fingerprint;
	
	//Those fields can't be marked as final because they may be left uninitialized...
	public long start_entry; //RVA - 0xFFFFFFFF if not present!
	public long stop_entry;  //RVA - 0xFFFFFFFF if not present!
	
	public long tls_top; //RVA - 0 if not present
	public long tls_filesz;
	public long tls_memsz;

	public long arm_exidx_top; //RVA
	public long arm_exidx_end; //RVA
	public long arm_extab_top; //RVA
	public long arm_extab_btm; //RVA

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
	
	private TypedefDataType MYTYPE = null;	
	public SceModuleInfo(BinaryReader reader) throws IOException {
		attributes = reader.readNextShort();
		version[0] = reader.readNextByte();
		version[1] = reader.readNextByte();
		
		assertValidName(reader);

		modname = reader.readNextAsciiString(27);
		
		infover = reader.readNextByte();
		if (infover == 1) {
			throw new MalformedElfException("struct _scemoduleinfo1 is not supported by Vita!");
		} else if (infover == 4 || infover == 5 || infover > 6) {
			throw new MalformedElfException(String.format("Module Info with infover %d is not supported by Vita!", infover));
		}

		//Fields common to all versions
		resreve = reader.readNextUnsignedInt(); //gp_value for _scemoduleinfo
		ent_top = reader.readNextUnsignedInt();
		ent_end = reader.readNextUnsignedInt();
		stub_top = reader.readNextUnsignedInt();
		stub_end = reader.readNextUnsignedInt();
		
		dbg_fingerprint = reader.readNextUnsignedInt();
		
		//Change according to version
		if (infover > 0 && infover < 6) {
			//sceModuleInfo1 fields
			start_entry = reader.readNextUnsignedInt();
			stop_entry = reader.readNextUnsignedInt();

			//sceModuleInfo_arm fields
			arm_exidx_top = reader.readNextUnsignedInt();
			arm_exidx_end = reader.readNextUnsignedInt();
			
			if (infover == 3) { //sceModuleInfo_arm_tls fields
				tls_top = reader.readNextUnsignedInt();
				tls_filesz = reader.readNextUnsignedInt();
				tls_memsz = reader.readNextUnsignedInt();
			}
		} else {
			tls_top = reader.readNextUnsignedInt();
			tls_filesz = reader.readNextUnsignedInt();
			tls_memsz = reader.readNextUnsignedInt();
			start_entry = reader.readNextUnsignedInt();
			stop_entry = reader.readNextUnsignedInt();
			arm_exidx_top = reader.readNextUnsignedInt();
			arm_exidx_end = reader.readNextUnsignedInt();
			arm_extab_top = reader.readNextUnsignedInt();
			arm_extab_btm = reader.readNextUnsignedInt();
		}
	}
	
	private DataType _getCommonDataType(DataType modAttrType) {	
		StructureDataType sdt = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, "_scemoduleinfo_common", 0);
		sdt.add(modAttrType, "modattribute", "Module attributes");
		sdt.add(Datatypes.makeArray(Datatypes.u8, 2), "modversion", "Module version [major.minor]");
		sdt.add(Datatypes.makeArray(Datatypes.char8, 26), "modname", "Module name");
		sdt.add(Datatypes.char8, "terminal", "Module name NUL terminator");
		sdt.add(Datatypes.s8, "infoversion", "Module info structure version (2 / 3 / 6)");

		return new TypedefDataType(Datatypes.SCE_TYPES_CATPATH, "sceModuleInfo_common", sdt);
	}
	
	public DataType toDataType(DataType moduleAttributesDataType) {		
		if (MYTYPE == null) {
			String _structureName = null;
			String _typedefName = null;
			switch(infover) {
			case 0:
				_structureName = "_scemoduleinfo";
				_typedefName = "sceModuleInfo";
				break;
			case 2:
				_structureName = "_scemoduleinfo_arm";
				_typedefName = "sceModuleInfo_arm";
				break;
			case 3:
				_structureName = "_scemoduleinfo_arm_tls";
				_typedefName = "sceModuleInfo_arm_tls";
				break;
			case 6:
				_structureName = "_scemoduleinfo_prx2arm";
				_typedefName = "sceModuleInfo_prx2arm";
				break;
			}
			
			//Elf32_Addr replacement, but not exactly the correct type !
			//But it's as good as we can do...
			//Maybe we shouldn't use it to not break analysis though :shrug:
			final DataType IBO32 = IBO32DataType.dataType;
			
			StructureDataType STRUCTURE = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, _structureName, 0);
			STRUCTURE.add(_getCommonDataType(moduleAttributesDataType), "c", null);
			STRUCTURE.add(Datatypes.u32, "resreve", "Reserved");
			STRUCTURE.add(IBO32, "ent_top", "Address of library entry table top");
			STRUCTURE.add(IBO32, "ent_end", "Address of library entry table end");
			STRUCTURE.add(IBO32, "stub_top", "Address of library stub table top");
			STRUCTURE.add(IBO32, "stub_end", "Address of library stub table end");
			
			
			//Change according to version
			if (infover > 0) {
				STRUCTURE.add(Datatypes.u32, "dbg_fingerprint", "Debug fingerprint (used to locate symbols)");
				
				if (infover < 6) {
					STRUCTURE.add(IBO32, "start_entry", "Address of the module_start entrypoint");
					STRUCTURE.add(IBO32, "stop_entry", "Address of the module_stop entrypoint");
									
					STRUCTURE.add(IBO32, "arm_exidx_top", "ARM EABI exception index table top");
					STRUCTURE.add(IBO32, "arm_exidx_end", "ARM EABI exception index table end");
					
					if (infover == 3) { //sceModuleInfo_arm_tls fields
						STRUCTURE.add(IBO32, "tls_start", "Address of TLS section top");
						STRUCTURE.add(Datatypes.u32, "tls_filesz", "Size of the TLS section (in file)");
						STRUCTURE.add(Datatypes.u32, "tls_memsz", "Size of the TLS section (in memory)");
					}
				} else {
					STRUCTURE.add(IBO32, "tls_top", "Address of TLS section top");
					STRUCTURE.add(Datatypes.u32, "tls_filesz", "Size of the TLS section (in file)");
					STRUCTURE.add(Datatypes.u32, "tls_memsz", "Size of the TLS section (in memory)");
					STRUCTURE.add(IBO32, "start_entry", "Address of the module_start entrypoint");
					STRUCTURE.add(IBO32, "stop_entry", "Address of the module_stop entrypoint");
					STRUCTURE.add(IBO32, "arm_exidx_top", "ARM EABI exception index table top");
					STRUCTURE.add(IBO32, "arm_exidx_end", "ARM EABI exception index table end");
					STRUCTURE.add(IBO32, "arm_extab_top", "ARM EABI exception table top");
					STRUCTURE.add(IBO32, "arm_extab_end", "ARM EABI exception table end");
				}
			}
			
			MYTYPE = new TypedefDataType(Datatypes.SCE_TYPES_CATPATH, _typedefName, STRUCTURE);
		}
		
		return MYTYPE;
	}
}
