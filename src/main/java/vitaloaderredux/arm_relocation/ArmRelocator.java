package vitaloaderredux.arm_relocation;

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.opinion.LoadException;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import vitaloaderredux.elf.MalformedElfException;

import vitaloaderredux.loader.ArmElfPrxLoaderContext;

import vitaloaderredux.misc.BitfieldReader;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;
import vitaloaderredux.misc.ImportExportProperty.IEKind;
import vitaloaderredux.misc.ImportExportProperty.IEType;

public class ArmRelocator {

	static public final int SIZE_OF_FORMAT_1_RELOCATION = 8;

	//Commented out types are not supported in reftable
	static private final int
		//R_ARM_NONE = 0,
		R_ARM_ABS32 = 2, R_ARM_TARGET1 = 38,
		R_ARM_REL32 = 3, R_ARM_TARGET2 = 41,
		R_ARM_THM_CALL = 10,
		R_ARM_CALL = 28,
		R_ARM_JUMP24 = 29,
		//R_ARM_V4BX = 40,
		R_ARM_PREL31 = 42,
		R_ARM_MOVW_ABS_NC = 43,
		R_ARM_MOVT_ABS = 44,
		R_ARM_THM_MOVW_ABS_NC = 47,
		R_ARM_THM_MOVT_ABS = 48,
		R_ARM_RBASE = 255;
	
	private final ArmElfPrxLoaderContext ctx;
	private final int __varImportBlockSize;
	private final int variableSize;
	private int curVariablesNum = 0;
	private final int maxVariablesNum;
	
	private MemoryBlock varImportBlock = null;
	private Address blockStartAddr;
	
	public ArmRelocator(ArmElfPrxLoaderContext context, int varImportBlockStartVA, int varImportBlockSize, int perVariableSize) throws Exception {
		ctx = context;
		variableSize = perVariableSize;
		__varImportBlockSize = varImportBlockSize;
		maxVariablesNum = varImportBlockSize / perVariableSize;
		
		blockStartAddr = ctx.getAddressInDefaultAS(varImportBlockStartVA);
	}
	
	private void __allocBlk() throws Exception {
		if (varImportBlock == null) {
			varImportBlock = ctx.memory.createUninitializedBlock("VarImport", blockStartAddr, __varImportBlockSize, false);
			
			varImportBlock.setRead(true);
			varImportBlock.setWrite(true);
			varImportBlock.setExecute(false);
			varImportBlock.setComment("Imported variables memory block");
		}
	}
	
	/**
	 * Obtain the size (in bytes) of a Prx2 format reftable.
	 * @param addr The address of the reftable
	 * @return The size of the relinfo
	 * @note This size includes the 32-bit header
	 */
	private int getPrx2RefInfoTableSize(Address tableAddr) throws MemoryAccessException, MalformedElfException  {
		int header = ctx.flatAPI.getInt(tableAddr);
		if ((header & 0xF000000F) != 0) {
			//N.B. old firmwares only check (& 0xF) == 0
			throw new MalformedElfException("Invalid reftable header");
		}
		return (header & 0x0FFFFFFF0) >>> 4;
	}
	
	/**
	 * Allocates a slot from the import variable slot.
	 * This function creates a label with the systematic name at the slot's address
	 * on behalf of the caller, and also registers it in the Imports/Exports table.
	 * @param libraryName
	 * @param variableNID
	 * @param tls true if slot is allocated for a TLS variable, false otherwise
	 * @return The address of the slot
	 * @throws Exception
	 */
	public Address allocateImportVariableSlot(String libraryName, int variableNID, boolean tls) throws Exception {
		__allocBlk();
		
		if (curVariablesNum >= maxVariablesNum) {
			throw new LoadException("Import variable block overflow");
		}
		
		Address varAddr = blockStartAddr.add(curVariablesNum * variableSize);
		ctx.flatAPI.createLabel(varAddr, Utils.getSystematicName(libraryName, variableNID), true);
		ctx.addImportExportEntry(varAddr, libraryName, variableNID, IEType.IMPORT, tls ? IEKind.TLS_VARIABLE : IEKind.VARIABLE);
		
		curVariablesNum++;
		
		return varAddr;
	}
	
	private int readInt(int va) throws MemoryAccessException {
		return ctx.flatAPI.getInt(ctx.getAddressInDefaultAS(va));
	}
	
	private void writeInt(int va, int val) throws MemoryAccessException {
		final Address dst = ctx.getAddressInDefaultAS(va);
		ctx.flatAPI.setInt(dst, val);
	}
	
	private void apply_one_relocation(int r_type, int S, int A, int P) throws MemoryAccessException, MalformedElfException {
		final int displacement = (A - P + S);
		
		switch (r_type) {
		case R_ARM_ABS32:
		case R_ARM_TARGET1: {
			writeInt(P, S + A);
			break;
		}
		
		case R_ARM_REL32:
		case R_ARM_TARGET2: {
			writeInt(P, displacement);
			break;
		}
			
		case R_ARM_THM_CALL: {
			//This is a Thumb opcode, actually make of two 16-bit parts.
			//Due to being read as a 32-bit integer, this results in them being reversed.
			//To read bit X of the first part (leftmost in the ARMARM), read bit (X).
			//To read bit X of the second part (rightmost in the ARMARM), read bit (X+16).
			int opcode = readInt(P);
			
			//Only bits 0x01FF_FFFE of the displacement are used.
			//Shift the displacement in advance to make the rest of the logic simpler.
			BitfieldReader displacementReader = new BitfieldReader(displacement >>> 1);
			
			int imm11 = displacementReader.consume(11);
			if ((opcode & ((1 << 12) << 16)) == 0) { //Bit 12 of 2nd part is clear: Encoding T2 (BLX)
				//In BLX, imm11 is actually imm10L:H where H must be 0 - otherwise, the instruction is undefined.
				//Ensure that bit H is clear by not copying it from the displacement.
				imm11 &= 0x7FE;
			}
			
			final int imm10 = displacementReader.consume(10);
			final int I1 = displacementReader.consume(1);
			final int I2 = displacementReader.consume(1);
			final int Sign  = displacementReader.consume(1); //Bit S in ARMARM
			
			displacementReader.assertConsumption("R_ARM_THM_CALL", 24);
			
			//I1 = NOT(J1 EOR S) --> J1 = NOT(I1) ^ S = (I1 == S)
			//I2 = NOT(J2 EOR S) --> J2 = NOT(I2) ^ S = (I2 == 2)			
			final int J1 = (I1 == Sign) ? 1 : 0;
			final int J2 = (I2 == Sign) ? 1 : 0;
			
			opcode &= 0xD000F800;
			opcode |= (S << 10) | imm10; //1st 16-bit part
			opcode |= ((J1 << 13) | (J2 << 11) | imm11) << 16; //2nd 16-bit part
			
			writeInt(P, opcode);
			break;
		}
			
		case R_ARM_CALL:
		case R_ARM_JUMP24: {
			int opcode = readInt(P);
			
			if ((opcode & 0xF0000000) == 0xF) { //BL,BLX (immediate) Encoding A2 - BLX
			
				//Original ASM is an optimized equivalent of:
				// opcode = (opcode & 0xFE7FFFFF) | (displacement & 0x3) << 23;
				//
				//This sets imm24's top bit, but imm24 will be cleared right after
				//so it's fine, and allows to use a single BFI instruction instead
				//of a shift+OR pair, saving both space and time.
				//
				//The original C code is probably something akin to what follows.
				
				//Set the H bit of the immediate, taken from bit 1 of the displacement.
				opcode = (opcode & 0xFEFFFFFF) | (displacement & 0x2) << 23;
			}
			opcode = (opcode & 0xFF000000) | (displacement >>> 2) & 0xFFFFFF;

			writeInt(P, opcode);			
			break;
		}
			
		case R_ARM_PREL31: {
			writeInt(P, displacement & 0x7FFFFFFF);
			break;
		}
			
			
		case R_ARM_MOVW_ABS_NC: {
			int opcode = readInt(P);
			
			final int target = (S + A);
			final int imm12 =  target & 0xFFF;
			final int imm4  = (target >>> 12) & 0xF;
			
			opcode &= 0xFFF0F000;
			opcode |= (imm4 << 16) | imm12;
			
			writeInt(P, opcode);			
			break;
		}
			
			
		case R_ARM_MOVT_ABS: {
			int opcode = readInt(P);
			
			final int target = (S + A);
			final int imm12 = (target >>> 16) & 0xFFF;
			final int imm4 =  (target >>> 28) & 0xF;
			
			opcode &= 0xFFF0F000;
			opcode |= (imm4 << 16) | imm12;
			
			writeInt(P, opcode);
			break;
		}
		
		case R_ARM_THM_MOVW_ABS_NC: {
			int opcode = readInt(P);
			
			final int target = (S + A);
			final int imm8 = target & 0xFF;
			final int imm3 = (target >>> 8)  & 0x7;
			final int imm1 = (target >>> 11) & 0x1;
			final int imm4 = (target >>> 12) & 0xF;
			
			opcode &= 0x8F00FBF0;
			opcode |= (imm8 << 16) | (imm3 << 28) | (imm1 << 10) | imm4;
			
			writeInt(P, opcode);			
			break;
		}
			
		case R_ARM_THM_MOVT_ABS: {
			int opcode = readInt(P);
			
			final int target = (S + A);
			final int imm8 = (target >>> 16) & 0xFF;
			final int imm3 = (target >>> 24)  & 0x7;
			final int imm1 = (target >>> 27) & 0x1;
			final int imm4 = (target >>> 28) & 0xF;

			opcode &= 0x8F00FBF0;
			opcode |= (imm8 << 16) | (imm3 << 28) | (imm1 << 10) | imm4;
			
			writeInt(P, opcode);			
			break;
		}
		
		//case R_ARM_NONE:
		//case R_ARM_V4BX:
		case R_ARM_RBASE:
			//Modulemgr ignores these entries
			break;
			
		default:
			throw new MalformedElfException("Unknown rel type " + r_type);
		}
	}
	
	private void markupInfo(StructConverter info, Address addr, int P) throws Exception {
		ctx.createData(addr, info.toDataType());
		ctx.listing.setComment(addr, CodeUnit.PRE_COMMENT, String.format("Relocation target: 0x%08X", P));
	}
	
	private void processPrx1Reftable(Address infoAddr, int destVA) throws Exception {
		while (ctx.flatAPI.getInt(infoAddr) != 0) {
			Prx1RefInfo info = new Prx1RefInfo(ctx.getBinaryReader(infoAddr));
			apply_one_relocation(info.reltype, destVA, info.addend, info.P);
			
			markupInfo(info, infoAddr, info.P);
			infoAddr = infoAddr.add(Prx1RefInfo.SIZE);
		}
	}
	
	private void processPrx2Reftable(Address infoAddr, Address maxAddr, int destVA) throws Exception {
		while (infoAddr.compareTo(maxAddr) < 0) {
			final int form = (ctx.flatAPI.getInt(infoAddr) & 0xF);
			switch (form) {
			case 1: {
				Prx2RefInfoForm1 info = new Prx2RefInfoForm1(ctx.getBinaryReader(infoAddr));
				final int P = (int)((ctx.elfEhdr.programHeaders[info.segment].p_vaddr + info.offset) & 0xFFFFFFFFL);
				
				apply_one_relocation(info.reltype, destVA, info.addend, P);
				
				markupInfo(info, infoAddr, P);
				infoAddr = infoAddr.add(Prx2RefInfoForm1.SIZE);
				break;
			}
			case 2: {
				Prx2RefInfoForm2 info = new Prx2RefInfoForm2(ctx.getBinaryReader(infoAddr));
				final int P = (int)((ctx.elfEhdr.programHeaders[info.segment].p_vaddr + info.offset) & 0xFFFFFFFFL);

				apply_one_relocation(info.reltype, destVA, info.addend, P);
				
				markupInfo(info, infoAddr, P);
				infoAddr = infoAddr.add(Prx2RefInfoForm2.SIZE);
				break;
			}
			default:
					throw new MalformedElfException("Invalid refinfo form " + form);
			}
		}
		
		if (infoAddr.compareTo(maxAddr) != 0) {
			throw new MalformedElfException("Reftable overflow");
		}
	}
	
	/**
	 * Parse a reference table and perform all the relocations it contains.
	 * @param refTableAddr 	Address of the reference table
	 * @param destAddr  	Address of the referenced data/function
	 */
	public void processReftable(Address refTableAddr, Address destAddr) throws Exception {
		__allocBlk();
		
		final int destVA = (int)destAddr.getUnsignedOffset();
		
		if (ctx.elfEhdr.isPrx1ELF()) {
			processPrx1Reftable(refTableAddr, destVA);
		} else {
			ctx.createData(refTableAddr, Datatypes.u32);
			final int tableSize = getPrx2RefInfoTableSize(refTableAddr);
			final Address refInfoAddr = refTableAddr.add(4);
			processPrx2Reftable(refInfoAddr, refTableAddr.add(tableSize), destVA);
		}
	}
}
