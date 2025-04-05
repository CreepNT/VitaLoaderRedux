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

public class TlsAllocReplacement {
	static public final int SIZE = 0x18;
	public static final String STRUCTURE_NAME = "SceTlsAllocReplacement";
	static public final CategoryPath TLS_ALLOC_REPLACE_CATPATH = new CategoryPath(Datatypes.SCE_LIBC_TYPES_CATPATH, "tlsreplace");

	public final int unk4;
	public final int user_malloc_for_tls_init;
	public final int user_malloc_for_tls_finalize;
	public final int user_malloc_for_tls;
	public final int user_free_for_tls;

	public TlsAllocReplacement(BinaryReader reader) throws IOException {
		final int size = reader.readNextInt();
		if (size != SIZE) {
			throw new MalformedElfException(String.format("Invalid TlsAllocReplacement size (0x%X != 0x%X)", size, SIZE));
		}

		unk4 = reader.readNextInt();
		user_malloc_for_tls_init = reader.readNextInt();
		user_malloc_for_tls_finalize = reader.readNextInt();
		user_malloc_for_tls = reader.readNextInt();
		user_free_for_tls = reader.readNextInt();

		Utils.assertBRSize(STRUCTURE_NAME, reader, size);
	}

	private FunctionDefinitionDataType
		F_user_malloc_for_tls_init, F_user_malloc_for_tls_finalize,
		F_user_malloc_for_tls, F_user_free_for_tls;

	@SafeVarargs
	private FunctionDefinitionDataType func(DataType returnType, String name, Map.Entry<DataType, String>... args) {
		return Datatypes.createFunctionDT(TLS_ALLOC_REPLACE_CATPATH, returnType, name, args);
	}

	private void __create_funcdef_dt() {
		if (F_user_malloc_for_tls_init == null) {
			final DataType VOID = VoidDataType.dataType;
			final DataType size_t = new TypedefDataType("size_t", Datatypes.u32);

			//Using void* instead of Pointer32DataType results in better decompilation.
			final DataType pVoid = new Pointer32DataType(VOID);

			//Create function signatures
			F_user_malloc_for_tls_init 		= func(VOID, "user_malloc_for_tls_init");
			F_user_malloc_for_tls_finalize 	= func(VOID, "user_malloc_for_tls_finalize");
			F_user_malloc_for_tls 			= func(pVoid, "user_malloc_for_tls", Map.entry(size_t, "count"));
			F_user_free_for_tls 			= func(VOID, "user_free_for_tls", Map.entry(pVoid, "ptr"));
		}
	}

	public DataType toDataType() {
		__create_funcdef_dt();
		StructureDataType dt = new StructureDataType(Datatypes.SCE_LIBC_TYPES_CATPATH, STRUCTURE_NAME, 0);
		dt.add(Datatypes.u32, "size", "Size of this structure");
		dt.add(Datatypes.u32, "unk4", null);
		dt.add(new Pointer32DataType(F_user_malloc_for_tls_init), "user_malloc_for_tls_init", "Initialization function for TLS alloc replacement");
		dt.add(new Pointer32DataType(F_user_malloc_for_tls_finalize), "user_malloc_for_tls_finalize", "Finalization function for TLS alloc replacement");
		dt.add(new Pointer32DataType(F_user_malloc_for_tls), "user_malloc_for_tls", "malloc_for_tls() replacement");
		dt.add(new Pointer32DataType(F_user_free_for_tls), "user_free_for_tls", "free_for_tls() replacement");

		if (dt.getLength() != SIZE)
			System.err.println("Unexpected " + STRUCTURE_NAME + " data type size (" + dt.getLength() + " != expected " + SIZE + " !)");

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
				Function f = ctx.markupFunction(name, va, "TLS memory allocation replacement function: " + name);
				ctx.setFunctionSignature(f, sig);
			}
		};

		mif.markup(user_malloc_for_tls_init, "user_malloc_for_tls_init", F_user_malloc_for_tls_init);
		mif.markup(user_malloc_for_tls_finalize, "user_malloc_for_tls_finalize", F_user_malloc_for_tls_finalize);
		mif.markup(user_malloc_for_tls, "user_malloc_for_tls", F_user_malloc_for_tls);
		mif.markup(user_free_for_tls, "user_free_for_tls", F_user_free_for_tls);
	}
}