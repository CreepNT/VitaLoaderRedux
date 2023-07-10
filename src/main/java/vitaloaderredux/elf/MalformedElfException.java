package vitaloaderredux.elf;

import ghidra.app.util.opinion.LoadException;

public class MalformedElfException extends LoadException {
	private static final long serialVersionUID = 6850465584723476757L;

	public MalformedElfException(String message) {
		super("Malformed ELF: " + message);
	}

	public MalformedElfException(Throwable cause) {
		super(cause);
	}
}
