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

//Form 1 reference information (used in reftables)
public class Prx2RefInfoForm1 implements StructConverter  {
	static public final int SIZE = 8;
	
	public final int segment;
	public final int offset;
	public final int addend;
	public final int reltype;
	
	public DataType toDataType() {
		StructureDataType dt = new StructureDataType(Datatypes.SCE_TYPES_CATPATH, "Prx2RefInfoForm1", 0);
		dt.setPackingEnabled(true);
		try {
			dt.addBitField(Datatypes.u32, 4, "form", "Refinfo form (must be 1)");
			dt.addBitField(Datatypes.u32, 4, "segment", "Segment where reference lies");
			dt.addBitField(Datatypes.u32, 8, "reltype", "Relocation type (r_type)");
			dt.addBitField(Datatypes.u32, 16, "addend", "Relocation addend (r_addend)");
		} catch (InvalidDataTypeException e) {
			throw new RuntimeException(e);
		}
		
		dt.add(Datatypes.u32, "offset", "Offset where reference lies in segment (r_offset)");
		
		Utils.assertStructureSize(dt, SIZE);
		return dt;
	}
	
	public Prx2RefInfoForm1(BinaryReader reader) throws IOException {
		BitfieldReader bfr = new BitfieldReader(reader.readNextInt());
		
		int form = bfr.consume(4);
		if (form != 1) {
			throw new IllegalArgumentException("Binary reader doesn't point to a form 1 RefInfo");
		}
		
		segment = bfr.consume(4);
		reltype = bfr.consume(8);
		addend = bfr.consumeSEXT(16);
		offset = reader.readNextInt();
		
		bfr.assertFullConsumption("Prx2RefInfoForm1");
		Utils.assertBRSize("Prx2RefInfoForm1", reader, SIZE);
	}
}
