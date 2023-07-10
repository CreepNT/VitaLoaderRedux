package vitaloaderredux.elf;

import ghidra.app.util.opinion.LoadException;

public class UnsupportedElfException extends LoadException {
	private static final long serialVersionUID = -8975223096035645703L;

	public UnsupportedElfException(String message) {
		super("Unsupported ELF: " + message);
	}

	public UnsupportedElfException(Throwable cause) {
		super(cause);
	}
}
