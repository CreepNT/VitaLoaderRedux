package vitaloaderredux.misc;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;


public class ProgramProcessingHelper {

	public final Memory memory;
	public final Listing listing;
	public final Program program;
	public final SymbolTable symTbl;
	public final FlatProgramAPI flatAPI;
	public final AddressSpace defaultAS;
	public final ExternalManager extMgr;
	public final FunctionManager funcMgr;
	public final ProgramContext programContext;
	public final PropertyMapManager usrPropMgr;
	
	private final RegisterValue ThumbTMode, ARMTMode;
	
	public ProgramProcessingHelper(Program p) {
		program = p;
		
		memory = program.getMemory();
		listing = program.getListing();
		symTbl = program.getSymbolTable();
		extMgr = program.getExternalManager();
		funcMgr = program.getFunctionManager();
		programContext = program.getProgramContext();
		usrPropMgr = program.getUsrPropertyManager();
		defaultAS = program.getAddressFactory().getDefaultAddressSpace();
		
		flatAPI = new FlatProgramAPI(program);
		
		Register TMode = programContext.getRegister("TMode");
		ThumbTMode = new RegisterValue(TMode, BigInteger.ONE);
		ARMTMode = new RegisterValue(TMode, BigInteger.ZERO);
	}
	
	public BinaryReader getBinaryReader(Address addr) {
		return new BinaryReader(new MemoryByteProvider(memory, addr), true);
	}
	
	public BinaryReader getBinaryReader(int va) {
		return getBinaryReader(getAddressInDefaultAS(va));
	}

	public Address getAddressInDefaultAS(int va) {
		//Due to sign extension, if VA has MSB set, we'll get a 'long' with bits 63-32 set.
		//This is completely wrong, so always clear top 32 bits before calling getTruncatedAddress().
		final long extendedVA = va & 0xFFFFFFFFl;
		return defaultAS.getTruncatedAddress(extendedVA, false /* irrelevant on ARM, getAddressableUnitSize() returns 1 */);
	}
	
	public Namespace getOrCreateNamespace(Namespace parent, String name) throws Exception {
		if (parent == null) {
			parent = program.getGlobalNamespace();
		}
		return symTbl.getOrCreateNameSpace(parent, name, SourceType.ANALYSIS);
	}
	
	public Data createData(Address address, DataType dt) throws CodeUnitInsertionException {
		Data old = listing.getDataAt(address);
		if (old != null && old.getDataType().isEquivalent(dt))
			return old;
		
		return DataUtilities.createData(program, address, dt, -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
	}
	
	//Creates data of type 'dt' and adds 'name' as the primary label of address 'addr' in namespace 'ns'
	public Data createLabeledDataInNamespace(Address addr, Namespace ns, String name, DataType type) throws Exception  {
		Data data = createData(addr, type);
		flatAPI.createLabel(addr, name, ns, true, SourceType.ANALYSIS);
		return data;
	}
	
	public IntBuffer readIntTable(Address addr, int numElements) throws MemoryAccessException {
		byte[] data = new byte[4 * numElements];
		MemoryBlock targetBlock = memory.getBlock(addr);
		targetBlock.getBytes(addr, data);
		
		return ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
	}
	
	public Function getImportFunction(String moduleFileName, String functionName) throws InvalidInputException, DuplicateNameException {
		ExternalLocation extLoc;
		if (moduleFileName == null) {
			extLoc = extMgr.addExtFunction((Namespace)null, functionName, null, SourceType.ANALYSIS);
		} else {
			extLoc = extMgr.addExtFunction(moduleFileName, functionName, null, SourceType.ANALYSIS);
		}
		return extLoc.getFunction();
	}
	
	//Creates a function at VA if none exists. Otherwise, simply adds 'name' as a label at VA.
	//If plateComment is non-null, set it as the function's plate comment, except if there already
	//is one - in this case, simply append it at the end of the existing plate comment.
	//TMode pseudo-register is automatically marked up - do NOT remove the bottom bit of VA!
	public Function markupFunction(String name, int va, String plateComment) throws Exception {
		final boolean isThumb = (va & 1) != 0;
		final Address funcAddr = getAddressInDefaultAS(va & ~1);
		
		Function f = funcMgr.getFunctionAt(funcAddr);
		if (f == null) {
			f = funcMgr.createFunction(name, funcAddr,
					(isThumb
					? new AddressSet(funcAddr, funcAddr.add(1))
					: new AddressSet(funcAddr, funcAddr.add(3))), SourceType.ANALYSIS);
			
			setTModeAtAddress(funcAddr, isThumb);
		} else {
			flatAPI.createLabel(funcAddr, name, false);
			String oldComment = f.getComment();
			if (oldComment != null && plateComment != null) {
				plateComment = oldComment + "\n\n" + plateComment;
			}
		}
		
		if (plateComment != null) {
			f.setComment(plateComment);
		}
		
		f.setCallingConvention("default");
		return f;
	}
	
	public void setFunctionSignature(Function func, FunctionDefinitionDataType signature) throws InvalidInputException, DuplicateNameException {
		func.setReturnType(signature.getReturnType(), SourceType.ANALYSIS);
		
		ParameterDefinition[] args = signature.getArguments();
		if (args.length > 0) {
			Variable[] vars = new Variable[args.length];
			for (int i = 0; i < args.length; i++) {
				vars[i] = new ParameterImpl(args[i].getName(), args[i].getDataType(), program);
			}
			
			func.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS, vars);
		}
		
	}
	
	private void setTModeAtAddress(Address addr, boolean TMode) throws ContextChangeException, AddressOutOfBoundsException  {
		if (TMode) {
			//Set register for the two bytes of the instruction
			programContext.setRegisterValue(addr, addr.add(1), ThumbTMode);
		} else {
			//Set register for the four bytes of the instruction
			programContext.setRegisterValue(addr, addr.add(3), ARMTMode);
		}
	}
}
