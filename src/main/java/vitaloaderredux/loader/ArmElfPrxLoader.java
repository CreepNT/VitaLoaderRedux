package vitaloaderredux.loader;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfProgramHeaderConstants;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;

import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.util.VoidPropertyMap;
import ghidra.util.MonitoredInputStream;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

import vitaloaderredux.elf.ElfEhdr;
import vitaloaderredux.elf.ElfEhdr.ModInfoLocation;
import vitaloaderredux.elf.ElfPhdr;
import vitaloaderredux.elf.ElfShdr;
import vitaloaderredux.elf.MalformedElfException;
import vitaloaderredux.elf.UnsupportedElfException;

import vitaloaderredux.misc.Datatypes;
import vitaloaderredux.misc.HexOption;
import vitaloaderredux.misc.ImportExportProperty;
import vitaloaderredux.scetypes.ILibent;
import vitaloaderredux.scetypes.ILibstub;
import vitaloaderredux.scetypes.SELFConstants;
import vitaloaderredux.scetypes.SceLibent_0x1C;
import vitaloaderredux.scetypes.SceLibent_0x20;
import vitaloaderredux.scetypes.SceLibstub_0x24;
import vitaloaderredux.scetypes.SceLibstub_0x2C;
import vitaloaderredux.scetypes.SceLibstub_0x34;
import vitaloaderredux.scetypes.SceModuleInfo;

/**
 * 
 * @author CreepNT
 *
 * @implNote This parser may be less strict than the SceKernelModulemgr (S)ELF parser.
 * Thus, getting a module to load properly with this loader is not a guarantee that
 * it will be accepted by SceKernelModulemgr.
 */
public class ArmElfPrxLoader extends AbstractLibrarySupportLoader {
	
	private static final LanguageCompilerSpecPair LANGUAGE = 
			new LanguageCompilerSpecPair("ARM:LE:32:v7", "default");

	public static final String MODULE_INFO_LOCATOR_USRPROPNAME = "[VLR:ARM] SceModuleInfo locator";
	public static final String IMPORTEXPORT_LOCATOR_USRPROPNAME = "[VLR:ARM] Imports/Exports locator";
	
	private static final String FILE_FORMAT_NAME = "ARM ELF-PRX for PlayStation\u00AEVita";
	
	private static final String VARIMPORT_BLOCK_ADDRESS_OPTNAME = "Variable Imports Block Base";
	private static final String VARIMPORT_BLOCK_SIZE_OPTNAME = "Variable Imports Block Size";
	private static final String VARIMPORT_SIZE_OPTNAME = "Imported Variables Size";
	
	private static final int NOACCESS = 0;
	private static final int PF_R = ElfProgramHeaderConstants.PF_R;
	private static final int PF_W = ElfProgramHeaderConstants.PF_W;
	private static final int PF_X = ElfProgramHeaderConstants.PF_X; 
	
	private static final Address OTHERAS_START = AddressSpace.OTHER_SPACE.getAddress(0);
		
	@Override
	public String getName() {
		return FILE_FORMAT_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		ElfEhdr ehdr;
		
		try {
			ehdr = new ElfEhdr(provider);
		} catch (IOException | IllegalArgumentException e) {
			return loadSpecs;
		}
		
		if (ehdr.e_machine != ElfConstants.EM_ARM)
			return loadSpecs;

		//Tiny sanity check: modules, check that SceModuleInfo.name field is valid.
		long modInfoOffset;
		try {
			modInfoOffset = ehdr.getModuleInfoFileOffset();
		} catch (MalformedElfException e) {
			System.err.println(e.getMessage());
			throw e;
		}
		if (modInfoOffset < 0) {
			return loadSpecs;
		}
		
		BinaryReader modInfoReader = new BinaryReader(provider, true);
		modInfoReader.setPointerIndex(modInfoOffset + 4);
		if (!SceModuleInfo.verifyModuleInfoName(modInfoReader, true)) {
			return loadSpecs;
		}
		
		loadSpecs.add(new LoadSpec(this, /* use a sensical default base address */ 0x81000000, LANGUAGE, true));
		return loadSpecs;
	}
	
	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
		
		//Place at end of address space with 4KiB per variable, up to 128 variables
		//Don't make block too big to avoid hindering navigation using the scroll bar!
		list.add(new HexOption(VARIMPORT_BLOCK_ADDRESS_OPTNAME, 0xF0000000L));
		list.add(new HexOption(VARIMPORT_BLOCK_SIZE_OPTNAME, 0x80000L));
		list.add(new HexOption(VARIMPORT_SIZE_OPTNAME, 0x1000L));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		if (options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(VARIMPORT_BLOCK_ADDRESS_OPTNAME) ||
					name.equals(VARIMPORT_BLOCK_SIZE_OPTNAME) ||
					name.equals(VARIMPORT_SIZE_OPTNAME)) {
					if (!Long.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type '" + option.getValueClass() + "' for option '" + name + "'";
					}
				}
			}
			
			final int varImportSize = getVarImportSize(options);
			final int varImportBlockSize = getVarImportBlockSize(options);
			
			if (varImportBlockSize < varImportSize) {
				return String.format("VarImport block size is lower than variable size", 
						varImportBlockSize, getVarImportSize(options));
			}
			
			if ((varImportBlockSize / varImportSize) == 0) {
				return "VarImport block too small to hold any variable";
			}
		}
		
		return super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return super.getTierPriority() - 1;
	}
	
	/* -------------------------------------------------- */
	
	ArmElfPrxLoaderContext ctx = null;
	FileBytes fileBytes = null;
	
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor taskMon, MessageLog log)
			throws CancelledException, IOException {
		
		//Initialize loader context
		ElfEhdr ehdr = new ElfEhdr(provider);
		
		//Set image base. This needs to be performed before any memory block is created
		//because it tries to shift all memory blocks, but VARIMPORT block at 0xF0000000
		//can't be and wraps around, causing an AddressOverflowException to be thrown.
		//
		//I don't know what the consequences of not setting the image base properly can be,
		//so do it just to save headaches in case it could utterly break something.
		try {
			//Do everything by hand because ctx is not initialized yet, and we can't initialize it
			//because it intializes the relocator which creates the very MemoryBlock that breaks everything!
			long imageBase = ehdr.getImageBase() & 0xFFFFFFFFl;
			Address imageBaseAddress = program.getAddressFactory().getDefaultAddressSpace().getAddress(imageBase);
			
			program.setImageBase(imageBaseAddress, true);
		} catch (AddressOverflowException | LockException | IllegalStateException | AddressOutOfBoundsException e) {
			throw new LoadException(e);
		}
		
		try {
			ctx = new ArmElfPrxLoaderContext(program, ehdr, taskMon, log, provider.length(), options);
		} catch (Exception e) {
			throw new LoadException(e);
		}
		
		//Obtain file bytes object from program
		try (InputStream fileIn = provider.getInputStream(0); MonitoredInputStream mis = new MonitoredInputStream(fileIn, taskMon)) {
			fileBytes = ctx.memory.createFileBytes(provider.getName(), 0, provider.length(), mis, taskMon);
		}
	
		//Markup ELF Ehdr, Phdrs and Shdrs
		createDataFromFileInOtherAS("ELF Ehdr", "ELF file header", 0, ElfEhdr.getDataType());
		createDataFromFileInOtherAS("ELF Phdrs", "ELF program headers", ehdr.e_phoff, Datatypes.makeArray(ElfPhdr.getDataType(), ehdr.e_phnum));
		if (ehdr.e_shnum > 0) {
			createDataFromFileInOtherAS("ELF Shdrs", "ELF section headers", ehdr.e_shoff, Datatypes.makeArray(ElfShdr.getDataType(), ehdr.e_shnum));
		}
		
		try {
			//Always parse segments even if sections may be available.
			//
			//This isn't a big deal because sections are effectively never present in
			//binaries we have (only in old SKBL modules which all have been looked at).
			//Regular ELF loader will process sections so use that if you really want them.
			loadSegments();
		} catch (Exception e) {
			throw new LoadException(e);
		}
		
		try {
			processModuleInfo();
		} catch (CancelledException | IOException e) { //Rethrow as-is on cancel or IOException
			throw e;
		} catch (Exception e) { //Otherwise, rethrow as LoadException
			throw new LoadException(e);
		}
		
		//TODO: implement symbol table support
		//SCE seems to use a non-standard(ish) symbol format, Ghidra chokes on it (all symbols are off-by-one).
		/*
		int fileIndex = 0;
		ElfSymbolTable[] symbolTables = elfHdr.getSymbolTables();
		for (ElfSymbolTable symbolTable : symbolTables) {
			monitor.checkCanceled();
			String[] files = symbolTable.getSourceFiles();
			for (String file : files) {
				monitor.checkCanceled();
				props.setString(ElfLoader.ELF_SOURCE_FILE_PROPERTY_PREFIX + pad(fileIndex++) + "]",
					file);
			}
		}
		*/
		
		//Set decorative metadata
		program.setExecutableFormat(ArmElfPrxLoader.FILE_FORMAT_NAME);
		addProgramProperties();
	}
	
	private void addProgramProperties() throws CancelledException {
		ctx.setMonitorMessage("Adding program properties...");
		
		Options properties = ctx.program.getOptions(Program.PROGRAM_INFO);
		properties.setString("ELF Type", ctx.elfEhdr.execType.description() + " (" + ctx.elfEhdr.execType.toString() + ")");
		properties.setBoolean("Relocatable", ctx.elfEhdr.execType.relocatable());
		properties.setString("Image Base Address", String.format("0x%08X", ctx.elfEhdr.getImageBase()));
		
		final String fileKind = ctx.getFileKind();
		if (fileKind != null) {
			properties.setString("File Kind", fileKind);
		}
		
		final String modSDKVersion = ctx.getModuleSDKVersion();
		if (modSDKVersion != null) {
			properties.setString("Module SDK Version", modSDKVersion);
		}
		
		final String ppSDKVersion = ctx.getProcessParamSDKVersion();
		if (ppSDKVersion != null) {
			properties.setString("Process Param SDK Version", ppSDKVersion);
		}
	}
	
	private MemoryBlock importPTLOADSegment(ElfPhdr Phdr, int index) throws Exception {
		//TODO: there is something special in p_flags that can extend the size of segments.
		//More Modulemgr RE is required...
		Address segmentLoadAddress = ctx.getAddressInDefaultAS((int)Phdr.p_vaddr);
		String segmentName = "seg" + index;
		MemoryBlock segmentBlock = null;
		
		if (Phdr.p_filesz > 0) {	
			//Create a memory block filled with file bytes
			segmentBlock = createFileBytesBlock(segmentName, segmentLoadAddress,
					Phdr.p_offset, Phdr.p_filesz, "", PhdrFlagsToMemPerms(Phdr.p_flags), false);
			
			//If memsz > filesz, expand by creating a tail memory block and merging the empty and filebytes blocks together
			if (Phdr.p_memsz > Phdr.p_filesz) {
				long zeroPadLen = Phdr.p_memsz - Phdr.p_filesz;
				
				MemoryBlock padBlk = createZeroInitializedBlock("dummy", segmentBlock.getEnd().add(1), zeroPadLen, "Loadable segment", NOACCESS, false);
				segmentBlock = ctx.memory.join(segmentBlock, padBlk);
			}
		} else if (Phdr.p_memsz > 0) {
			//It is possible that the RW segment contains only .bss (no uninitialized static data).
			//In this case, simply create a zero-initialized segment.
			
			segmentBlock = createZeroInitializedBlock(segmentName, segmentLoadAddress, Phdr.p_memsz, "Zero-initialized segment", PhdrFlagsToMemPerms(Phdr.p_flags), false);			
		} else {
			ctx.logf("Skipped zero-length segment #%d (PT_LOAD segment, file offset 0x%X, flags 0x%X)", index, Phdr.p_offset, Phdr.p_flags);
		}
		Phdr.userData = segmentBlock;
		return segmentBlock;
	}

	//Initializes Phdr.userData to the corresponding MemoryBlock object.
	private void loadSegments() throws Exception {
		ctx.startCountableTask("Loading program segments...", ctx.elfEhdr.e_phnum);
		
		int numLoadedPTLOADSegments = 0;
		for (int i = 0; i < ctx.elfEhdr.e_phnum; i++, ctx.incrementTaskProgress()) {
			ElfPhdr Phdr = ctx.elfEhdr.programHeaders[i];
	
			if (Phdr.p_type == ElfProgramHeaderConstants.PT_NULL)
				continue;
			
			if (Phdr.p_type == ElfProgramHeaderConstants.PT_LOAD) {
				if (importPTLOADSegment(Phdr, i) != null) {
					numLoadedPTLOADSegments++;
				}
			} else if (
					Phdr.p_type == ElfPhdr.PT_SCE_RELA ||
					Phdr.p_type == ElfPhdr.PT_SCE_COMMENT || 
					Phdr.p_type == ElfPhdr.PT_SCE_VERSION ||
					Phdr.p_type == ElfPhdr.PT_ARM_UNWIND   ||
					Phdr.p_type == ElfPhdr.PT_SCE_ARMRELA) {
				String segmentName = null, comment = null;
				switch ((int)Phdr.p_type) {
				case ElfPhdr.PT_SCE_RELA: {
					segmentName = "SCE_RELA";
					comment = "Relocation segment";
					break;
				}
				case ElfPhdr.PT_SCE_COMMENT: {
					segmentName = "SCE_COMMENT";
					comment = "Toolchain comment segment";
					break;
				}
				case ElfPhdr.PT_SCE_VERSION: {
					segmentName = "SCE_VERSION";
					comment = "Toolchain version segment";
					break;
				}
				case ElfPhdr.PT_ARM_UNWIND: {
					segmentName = "ARM_UNWIND";
					comment = "Exception unwind tables segment";
					break;
				}
				case ElfPhdr.PT_SCE_ARMRELA: {
					segmentName = "ARMRELA";
					comment = "PRX1 relocation segment";
					break;
				}
				}
				
				//Check that the segment is not empty and belongs in the file
				if (Phdr.p_filesz <= 0) {
					ctx.logf("Skipped zero-length segment #%d (%s)", i, comment.toLowerCase());
				} else if (Phdr.p_offset > ctx.fileSize || (Phdr.p_offset + Phdr.p_filesz) > ctx.fileSize) {
					ctx.logf("Skipped segment #%d (%s) spanning outside file", i, comment.toLowerCase());
				} else {
					Phdr.userData = createFileBytesBlock("seg0" + i + "_" + segmentName, OTHERAS_START, Phdr.p_offset, Phdr.p_filesz, comment, NOACCESS, true);
				}
			} else {
				ctx.logf("Skipped segment #%d (unknown segment type 0x%X)", i, Phdr.p_type);
			}
		}
		
		ctx.setMonitorMessage("Post-processing segments...");
		
		//Check if PT_LOAD segments are candidate for '.text'/'.data' naming
		if (numLoadedPTLOADSegments == 1 || numLoadedPTLOADSegments == 2) {
			ElfPhdr textSegment = null, dataSegment = null;
			for (ElfPhdr Phdr: ctx.elfEhdr.programHeaders) {
				//Only check PT_LOAD segments that were loaded (non-null memory block object in userData).
				if (Phdr.p_type == ElfProgramHeaderConstants.PT_LOAD && Phdr.userData != null) {
					int perms = PhdrFlagsToMemPerms(Phdr.p_flags);
					if (perms == (PF_R) || perms == (PF_R | PF_W)) {
						dataSegment = Phdr;
					} else if (perms == (PF_R | PF_X)) {
						textSegment = Phdr;
					}
				}
			}
			
			if (textSegment != null && (numLoadedPTLOADSegments == 1 || dataSegment != null)) {
				((MemoryBlock)textSegment.userData).setName(".text");
				if (dataSegment != null) {
					((MemoryBlock)dataSegment.userData).setName(".data");
				}
			}
		}
	}

	private void processModuleInfo() throws Exception {
		ctx.setMonitorMessage("Processing SceModuleInfo...");
		ModInfoLocation loc = ctx.elfEhdr.getModuleInfoLocation();
		if (loc == null) {
			throw new UnsupportedElfException("Cannot find SceModuleInfo location");
		}
		
		//Read SceModuleInfo
		Address modInfoSegmentBase = getSegmentStartAddress(ctx.elfEhdr.programHeaders[loc.segmentIndex]);
		Address modInfoAddr = modInfoSegmentBase.add(loc.segmentOffset);
		SceModuleInfo modInfo = new SceModuleInfo(ctx.getBinaryReader(modInfoAddr));

		//Create module namespace
		ctx.moduleNamespace = ctx.getOrCreateNamespace(null, "#" + modInfo.modname);

		//Markup __sce_moduleinfo and add in module namespace
		DataType moduleAttributes = SELFConstants.createModuleAttributesDataType(ctx.program.getDataTypeManager(), Datatypes.SCE_TYPES_CATPATH);
		ctx.createLabeledDataInNamespace(modInfoAddr, ctx.moduleNamespace, "__sce_moduleinfo", modInfo.toDataType(moduleAttributes));
		
		//Parse imports if available
		if (modInfo.libstub_top != modInfo.libstub_btm) {
			//NOTE: it is not valid to create an address from libstub_btm
			//because it may not belong in the address space covered by the ELF.
			Address firstLibstub = modInfoSegmentBase.add(modInfo.libstub_top);
			
			//Read-ahead the size of the libstub used in this SELF.
			//Since mixing different libstub structures is illegal,
			//this allows us to know how many of them there are.
			final int libstubSize = ctx.getBinaryReader(firstLibstub).readNextUnsignedShort();
			final long libstubBlockSize = modInfo.libstub_btm - modInfo.libstub_top;
			if ((libstubBlockSize % libstubSize) != 0) {
				throw new MalformedElfException("Libstub block size is not a multiple of the libstub size!");
			}
			final int numLibstubs = (int)(libstubBlockSize / libstubSize);
			
			ctx.startCountableTask("Processing imports...", numLibstubs);
			
			for (int i = 0; i < numLibstubs; i++, ctx.incrementTaskProgress()) {
				Address currentLibstub = firstLibstub.add(i * libstubSize);
				BinaryReader libstubReader = ctx.getBinaryReader(currentLibstub);
				ILibstub libstub;
				switch(libstubSize) {
				case SceLibstub_0x24.SIZE:
					libstub = new SceLibstub_0x24(libstubReader);
					break;
				case SceLibstub_0x2C.SIZE:
					libstub = new SceLibstub_0x2C(libstubReader);
					break;
				case SceLibstub_0x34.SIZE:
					libstub = new SceLibstub_0x34(libstubReader);
					break;
				default:
					throw new UnsupportedElfException(String.format("Unknown Libstub size 0x%X", libstubSize));
				}
				
				libstub.process(ctx, currentLibstub);
			}
			
			ctx.endCountableTask();
		}
		
		//Parse exports if available
		if (modInfo.libent_top != modInfo.libent_btm) {
			boolean hasSeenMAINEXPORT = false;
			
			//NOTE: it is not valid to create an address from libent_btm
			//because it may not belong in the address space covered by the ELF.
			final Address firstLibent = modInfoSegmentBase.add(modInfo.libent_top);

			//Read-ahead the size of the libstub used in this SELF.
			//Since mixing different libstub structures is illegal,
			//this allows us to know how many of them there are.
			final int libentSize = ctx.getBinaryReader(firstLibent).readNextUnsignedShort();
			final long libentBlockSize = modInfo.libent_btm - modInfo.libent_top;
			if ((libentBlockSize % libentSize) != 0) {
				throw new MalformedElfException("Libent block size is not a multiple of the libent size!");
			}
			final int numLibents = (int)(libentBlockSize / libentSize);
			
			ctx.startCountableTask("Processing exports...", numLibents);
			
			for (int i = 0; i < numLibents; i++, ctx.incrementTaskProgress()) {
				Address currentLibent = firstLibent.add(i * libentSize);
				BinaryReader libentReader = ctx.getBinaryReader(currentLibent);
				ILibent libent;
				switch (libentSize) {
				case SceLibent_0x1C.SIZE:
					libent = new SceLibent_0x1C(libentReader);
					break;
				case SceLibent_0x20.SIZE:
					libent = new SceLibent_0x20(libentReader);
					break;
				default:
					throw new UnsupportedElfException(String.format("Unknown Libent size 0x%X", libentSize));
				}
				
				if ((libent.getAttributes() & SELFConstants.SCE_LIBRARY_ATTR_MAIN_EXPORT) != 0) {
					if (hasSeenMAINEXPORT) {
						throw new MalformedElfException("More than one MAINEXPORT library.");
					}
					hasSeenMAINEXPORT = true;
				}
				
				libent.process(ctx, currentLibent);
			}
			
			ctx.endCountableTask();
			
			if (!hasSeenMAINEXPORT) {
				throw new MalformedElfException("No MAINEXPORT library.");
			}
		}
		
		ctx.setMonitorMessage("Processing SceModuleInfo...");
		
		//Markup exidx, extab and TLS
		if (modInfo.exidx_top < modInfo.exidx_btm) {
			final int size = (int)(modInfo.exidx_btm - modInfo.exidx_top);
			if (size < 0) {
				throw new MalformedElfException("exidx overflow");
			}
			
			Address exidx = modInfoSegmentBase.add(modInfo.exidx_top);
			ctx.createLabeledDataInNamespace(exidx, ctx.moduleNamespace, "exidx", Datatypes.makeArray(ByteDataType.dataType, size));
		}
		
		if (modInfo.extab_top < modInfo.extab_btm) {
			final int size = (int)(modInfo.extab_btm - modInfo.extab_top);
			if (size < 0) {
				throw new MalformedElfException("extab overflow");
			}
			
			Address extab = modInfoSegmentBase.add(modInfo.extab_top);
			ctx.createLabeledDataInNamespace(extab, ctx.moduleNamespace, "extab", Datatypes.makeArray(ByteDataType.dataType, size));
		}
		
		if (modInfo.tls_top != 0 && modInfo.tls_memsz != 0) {
			Address tls_start = modInfoSegmentBase.add(modInfo.tls_top);
			Address tls_end = tls_start.add(modInfo.tls_memsz - 1);
			ctx.listing.setComment(tls_start, CodeUnit.PRE_COMMENT, "--- TLS data start ---");
			ctx.listing.setComment(tls_end, CodeUnit.POST_COMMENT, "--- TLS data end ---");
			try {
				ctx.createLabeledDataInNamespace(tls_start, ctx.moduleNamespace, "tls", Datatypes.makeArray(ByteDataType.dataType, (int)modInfo.tls_memsz));
			} catch (CodeUnitInsertionException e) {
				ctx.logf("Could not markup TLS data due to a data conflict");
			}
		}
		
		//Create a property map that indicates this is a Vita ELF, and can be used by analyzers
		//and scripts to locate the SceModuleInfo structure and its segment base trivially.
		try {
			VoidPropertyMap vpm = ctx.usrPropMgr.createVoidPropertyMap(MODULE_INFO_LOCATOR_USRPROPNAME);
			vpm.add(modInfoSegmentBase);
			vpm.add(modInfoAddr);
		} catch (DuplicateNameException e) {
			//Rethrow as LoadException on failure because this is fatal
			//(but should never happen)
			throw new LoadException(e);
		}
	}

	/* -------------- Utility functions -------------- */
	
	//On any Exception, returns null and logs to MessageLog.
	private Data createDataFromFileInOtherAS(String blockName, String comment, long fileOffset, DataType dt) throws CancelledException {
		ctx.monitor.checkCancelled();
		try {
			MemoryBlock blk = createFileBytesBlock(blockName, OTHERAS_START, fileOffset, dt.getLength(), comment, NOACCESS, true);
			Address dst = blk.getStart();
			return ctx.createData(dst, dt);
		} catch (CodeUnitInsertionException | AddressOverflowException e) {
			ctx.logf("Failed creation of file data '%s' in OTHERAS due to the following exception:", blockName);
			ctx.logger.appendException(e);
			return null;
		}
	}
	
	private MemoryBlock createZeroInitializedBlock(String name, Address start,
			long length, String comment, int perms, boolean isOverlay) throws CancelledException {
		ctx.monitor.checkCancelled();
		boolean r = (perms & PF_R) != 0,
				w = (perms & PF_W) != 0,
				x = (perms & PF_X) != 0;
		
		return MemoryBlockUtils.createInitializedBlock(ctx.program, isOverlay, name, start,
				length, comment, "", r, w, x, ctx.logger);
	}
	
	private MemoryBlock createFileBytesBlock(String name, Address start, long fileOffset,
			long length, String comment, int perms, boolean isOverlay) throws AddressOverflowException, CancelledException {
		ctx.monitor.checkCancelled();
		boolean r = (perms & PF_R) != 0,
				w = (perms & PF_W) != 0,
				x = (perms & PF_X) != 0;
		
		return MemoryBlockUtils.createInitializedBlock(ctx.program, isOverlay, name, start,
				fileBytes, fileOffset, length, comment, this.getName(), r, w, x, ctx.logger);

	}

	private static Address getSegmentStartAddress(ElfPhdr segment) {
		return ((MemoryBlock)segment.userData).getStart();
	}
	
	private static int PhdrFlagsToMemPerms(long p_flags) {
		return (int)(p_flags & (PF_R | PF_W | PF_X));
	}

	/* Exported utility functions */
	
	public static int getVarImportBlockVA(List<Option> options) {
		return OptionUtils.getOption(VARIMPORT_BLOCK_ADDRESS_OPTNAME, options, 0xF0000000L).intValue();
	}
	
	public static int getVarImportBlockSize(List<Option> options) {
		return OptionUtils.getOption(VARIMPORT_BLOCK_SIZE_OPTNAME, options, 0x10000000L).intValue();
	}
	
	public static int getVarImportSize(List<Option> options) {
		return OptionUtils.getOption(VARIMPORT_SIZE_OPTNAME, options, 0x1000L).intValue();
	}
	
	public static boolean isArmExecutable(Program program) {
		return (program.getUsrPropertyManager().getVoidPropertyMap(MODULE_INFO_LOCATOR_USRPROPNAME) != null);
	}
	
	public static Address getModuleInfoSegmentBaseAddressFromVPM(Program program) {
		//By definition, the segment base is <= SceModuleInfo address, thus it's first.
		return program.getUsrPropertyManager().getVoidPropertyMap(MODULE_INFO_LOCATOR_USRPROPNAME).getFirstPropertyAddress();
	}
	
	public static Address getModuleInfoAddressFromVPM(Program program) {
		//Since the segment base is first, the SceModuleInfo must be second i.e. next after the first.
		VoidPropertyMap vpm = program.getUsrPropertyManager().getVoidPropertyMap(MODULE_INFO_LOCATOR_USRPROPNAME);
		return vpm.getNextPropertyAddress(vpm.getFirstPropertyAddress());
	}
	
	@SuppressWarnings("unchecked")
	public static ObjectPropertyMap<ImportExportProperty> getImportExportPropertyMap(Program program) {
		return (ObjectPropertyMap<ImportExportProperty>)program.getUsrPropertyManager().getObjectPropertyMap(IMPORTEXPORT_LOCATOR_USRPROPNAME);
	}
}
