package vitaloaderredux.scetypes.libc;

import java.io.IOException;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.loader.ArmElfPrxLoaderContext;
import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.Utils;

public class LibcAllocReplacement {
	static public final int SIZE = 0x34;
	static public final String STRUCTURE_NAME = "SceLibcAllocReplacement";
	static public final CategoryPath LIBC_ALLOC_REPLACE_CATPATH = new CategoryPath(Datatypes.SCE_LIBC_TYPES_CATPATH, "libcallocreplace");
	
	public final int unk4;
	public final int user_malloc_init;
	public final int user_malloc_finalize;
	public final int user_malloc;
	public final int user_free;
	public final int user_calloc;
	public final int user_realloc;
	public final int user_memalign;
	public final int user_reallocalign;
	public final int user_malloc_stats;
	public final int user_malloc_stats_fast;
	public final int user_malloc_usable_size;
	
	public LibcAllocReplacement(BinaryReader reader) throws IOException {
		final int size = reader.readNextInt();
		if (size != SIZE) {
			throw new MalformedElfException(String.format("Invalid LibcAllocReplacement size (0x%X != 0x%X)", size, SIZE));
		}
		
		unk4 = reader.readNextInt();
		user_malloc_init = reader.readNextInt();
		user_malloc_finalize = reader.readNextInt();
		user_malloc = reader.readNextInt();
		user_free = reader.readNextInt();
		user_calloc = reader.readNextInt();
		user_realloc = reader.readNextInt();
		user_memalign = reader.readNextInt();
		user_reallocalign = reader.readNextInt();
		user_malloc_stats = reader.readNextInt();
		user_malloc_stats_fast = reader.readNextInt();
		user_malloc_usable_size = reader.readNextInt();
		
		Utils.assertBRSize(STRUCTURE_NAME, reader, size);
	}
	
	private FunctionDefinitionDataType
		F_user_malloc_init, F_user_malloc_finalize, F_user_malloc, F_user_free,
		F_user_calloc, F_user_realloc, F_user_memalign, F_user_reallocalign,
		F_user_malloc_stats, F_user_malloc_stats_fast, F_user_malloc_usable_size;
	
	@SafeVarargs
	private FunctionDefinitionDataType func(DataType returnType, String name, Map.Entry<DataType, String>... args) {
		return Datatypes.createFunctionDT(LIBC_ALLOC_REPLACE_CATPATH, returnType, name, args);
	}
	
	private void __create_funcdef_dt() {
		if (F_user_malloc_init == null) {
			//Local declarations for convenience
			final DataType size_t = new TypedefDataType("size_t", Datatypes.u32);
			final DataType sint = Datatypes.s32;
			final DataType VOID = VoidDataType.dataType;
			
			//Using void* instead of Pointer32DataType results in better decompilation.
			final DataType pVoid = new Pointer32DataType(VOID);
			
			//Create malloc_managed_size struct
			StructureDataType mmsize = new StructureDataType(LIBC_ALLOC_REPLACE_CATPATH, "malloc_managed_size", 8 * 4);
			mmsize.add(size_t, "max_system_size", null);
			mmsize.add(size_t, "current_system_size", null);
			mmsize.add(size_t, "max_inuse_size", null);
			mmsize.add(size_t, "current_inuse_size", null);
			mmsize.add(Datatypes.makeArray(size_t, 4), "reserved", "Reserved area");
			DataType pmmsize = new Pointer32DataType(mmsize);
			
			//Create function signatures
			F_user_malloc_init 		= func(VOID, "user_malloc_init");
			F_user_malloc_finalize 	= func(VOID, "user_malloc_finalize");
			F_user_malloc 			= func(pVoid, "user_malloc", Map.entry(size_t, "size"));
			F_user_free 			= func(VOID, "user_free", Map.entry(pVoid, "size"));
			
			F_user_calloc 		= func(pVoid, "user_calloc", Map.entry(size_t, "nelem"), Map.entry(size_t, "size"));
			F_user_realloc 		= func(pVoid, "user_realloc", Map.entry(pVoid, "ptr"), Map.entry(size_t, "size"));
			F_user_memalign 	= func(pVoid, "user_memalign", Map.entry(size_t, "boundary"), Map.entry(size_t, "size"));
			F_user_reallocalign = func(pVoid, "user_reallocalign", Map.entry(pVoid, "ptr"), Map.entry(size_t, "size"), Map.entry(size_t, "boundary"));
			
			F_user_malloc_stats			= func(sint, "user_malloc_stats", Map.entry(pmmsize, "mmsize"));
			F_user_malloc_stats_fast 	= func(sint, "user_malloc_stats_fast", Map.entry(pmmsize, "mmsize"));
			F_user_malloc_usable_size 	= func(size_t, "user_malloc_usable_size", Map.entry(pVoid, "ptr"));
		}
	}
	
	public DataType toDataType() {
		__create_funcdef_dt();
		StructureDataType dt = new StructureDataType(Datatypes.SCE_LIBC_TYPES_CATPATH, STRUCTURE_NAME, 0);
		dt.add(Datatypes.u32, "size", "Size of this structure");
		dt.add(Datatypes.u32, "unk4", null);
		dt.add(new Pointer32DataType(F_user_malloc_init), "user_malloc_init", "Initialization function for libc alloc replacement");
		dt.add(new Pointer32DataType(F_user_malloc_finalize), "user_malloc_finalize", "Finalization function for libc alloc replacement");
		dt.add(new Pointer32DataType(F_user_malloc), "user_malloc", "malloc() replacement");
		dt.add(new Pointer32DataType(F_user_free), "user_free", "free() replacement");
		dt.add(new Pointer32DataType(F_user_calloc), "user_calloc", "calloc() replacement");
		dt.add(new Pointer32DataType(F_user_realloc), "user_realloc", "realloc() replacement");
		dt.add(new Pointer32DataType(F_user_memalign), "user_memalign", "memalign() replacement");
		dt.add(new Pointer32DataType(F_user_reallocalign), "user_reallocalign", "reallocalign() replacement");
		dt.add(new Pointer32DataType(F_user_malloc_stats), "user_malloc_stats", "memory statistics query function");
		dt.add(new Pointer32DataType(F_user_malloc_stats_fast), "user_malloc_stats_fast", "fast memory statistics query function");
		dt.add(new Pointer32DataType(F_user_malloc_usable_size), "user_malloc_usable_size", "allocation size query function");
		
		Utils.assertStructureSize(dt, SIZE);
		return dt;
	}
	
	private interface MarkupIF {
		void markup(int va, String name, FunctionDefinitionDataType sig) throws Exception;
	}
	
	public void process(ArmElfPrxLoaderContext ctx) throws Exception {
		__create_funcdef_dt();
		
		MarkupIF mif = (va, name, sig) -> {
			if (va != 0) {
				Function f = ctx.markupFunction(name, va, "libc replacement function: " + name);
				ctx.setFunctionSignature(f, sig);
			}
		};
		
		//Markup functions
		mif.markup(user_malloc_init, "user_malloc_init", F_user_malloc_init);
		mif.markup(user_malloc_finalize, "user_malloc_finalize", F_user_malloc_finalize);
		mif.markup(user_malloc, "user_malloc", F_user_malloc);
		mif.markup(user_free, "user_free", F_user_free);
		mif.markup(user_calloc, "user_calloc", F_user_calloc);
		mif.markup(user_realloc, "user_realloc", F_user_realloc);
		mif.markup(user_memalign, "user_memalign", F_user_memalign);
		mif.markup(user_reallocalign, "user_reallocalign", F_user_reallocalign);
		mif.markup(user_malloc_stats, "user_malloc_stats", F_user_malloc_stats);
		mif.markup(user_malloc_stats_fast, "user_malloc_stats_fast", F_user_malloc_stats_fast);
		mif.markup(user_malloc_usable_size, "user_malloc_usable_size", F_user_malloc_usable_size);
	}
}