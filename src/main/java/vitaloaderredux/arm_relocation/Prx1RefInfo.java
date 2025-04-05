package vitaloaderredux.arm_relocation;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.StructureDataType;
import vitaloaderredux.misc.BitfieldReader;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;

//Prx1 reference information
public class Prx1RefInfo implements StructConverter {
	static public final int SIZE = 8;

	public final int reltype;
	public final int addend;
	public final int P;

	public DataType toDataType() {
		StructureDataType dt = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, "Prx1RefInfo", 0);
		dt.setPackingEnabled(true);
		try {
			dt.addBitField(Datatypes.u32, 8, "reltype", "Relocation type (r_type)");
			dt.addBitField(Datatypes.u32, 24, "addend", "Relocation addend (r_addend)");
		} catch (InvalidDataTypeException e) {
			throw new RuntimeException(e);
		}

		dt.add(Datatypes.ptr, "P", "Virtual address where the reference lies");


		Utils.assertStructureSize(dt, SIZE);
		return dt;
	}

	public Prx1RefInfo(BinaryReader reader) throws IOException {
		BitfieldReader bfr = new BitfieldReader(reader.readNextInt());

		reltype = bfr.consume(8);
		addend = bfr.consumeSEXT(24);
		P = reader.readNextInt();

		bfr.assertFullConsumption("Prx1RefInfo");
		Utils.assertBRSize("Prx1RefInfo", reader, SIZE);
	}

}