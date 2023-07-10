package vitaloaderredux.misc;

import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;
import ghidra.util.classfinder.ExtensionPoint;

public class ImportExportProperty implements Saveable, ExtensionPoint {

	public enum IEType {
		IMPORT, EXPORT, INVALID;

		byte pack() {
			if (this == IMPORT)
				return 0x1;
			if (this == EXPORT)
				return 0x2;
			return -1;
		}

		static IEType unpack(byte val) {
			if (val == 0x1)
				return IMPORT;
			if (val == 0x2)
				return EXPORT;
			return INVALID;
		}
	}

	static public enum IEKind {
		FUNCTION, VARIABLE, TLS_VARIABLE, INVALID;

		byte pack() {
			if (this == FUNCTION)
				return 0x1;
			if (this == VARIABLE)
				return 0x2;
			if (this == TLS_VARIABLE)
				return 0x3;
			return -1;
		}

		static IEKind unpack(byte val) {
			if (val == 0x1)
				return FUNCTION;
			if (val == 0x2)
				return VARIABLE;
			if (val == 0x3)
				return TLS_VARIABLE;
			return INVALID;
		}
	}

	private String libName;
	private int NID;
	private IEType type;
	private IEKind kind;

	public String getLibraryName() { return libName; }
	public int getNID() { return NID; }
	public IEType getType() { return type; }
	public IEKind getKind() { return kind; }
	
	public ImportExportProperty() {}
	
	//As an optimization, we may want to store the VA of the library name instead of the name itself.
	//Although, even in the worse scenario of ~400 imports/exports per file, knowing each library name
	//takes up to 27 bytes, this shouldn't consume more than a few KBs.
	public ImportExportProperty(String libraryName, int thingNID, IEType importOrExport, IEKind kindOfIE) {
		libName = libraryName;
		NID = thingNID;
		type = importOrExport;
		kind = kindOfIE;
	}

	@Override
	public int getSchemaVersion() {
		return 0;
	}

	@Override
	public Class<?>[] getObjectStorageFields() {
		return new Class[] { String.class, Integer.class, Byte.class, Boolean.class };
	}

	/*
	 * Version 0:
	 * 	String libraryName;
	 *  int NID;
	 *  byte type;
	 *  byte kind;
	 */
	public void save_restore_SchemaVersion0(ObjectStorage objStorage, boolean save) {
		if (save) {
			objStorage.putString(libName);
			objStorage.putInt(NID);
			objStorage.putByte(type.pack());
			objStorage.putByte(kind.pack());
		} else {
			libName = objStorage.getString();
			NID = objStorage.getInt();
			type = IEType.unpack(objStorage.getByte());
			kind = IEKind.unpack(objStorage.getByte());
		}
	}

	@Override
	public void save(ObjectStorage objStorage) {
		save_restore_SchemaVersion0(objStorage, true);
	}

	@Override
	public void restore(ObjectStorage objStorage) {
		save_restore_SchemaVersion0(objStorage, false);
	}

	@Override
	public boolean isUpgradeable(int oldSchemaVersion) {
		return false;
	}

	@Override
	public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion, ObjectStorage currentObjStorage) {
		return false;
	}

	@Override
	public boolean isPrivate() {
		return false;
	}
}
