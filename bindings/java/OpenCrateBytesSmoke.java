import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;

/** Java 22+ Foreign Function & Memory example; no JNI or third-party jar. */
public final class OpenCrateBytesSmoke {
    private static final int OK = 0;
    private static final int CRYPTO = 7;

    private static void check(int status, String operation) {
        if (status != OK) {
            throw new IllegalStateException(operation + " failed with status " + status);
        }
    }

    public static void main(String[] args) throws Throwable {
        String library = System.getenv("OPENCRATE_FFI_LIB");
        if (library == null) {
            throw new IllegalArgumentException("Set OPENCRATE_FFI_LIB to the native library path");
        }
        try (Arena arena = Arena.ofConfined()) {
            Linker linker = Linker.nativeLinker();
            SymbolLookup symbols = SymbolLookup.libraryLookup(Path.of(library), arena);
            MethodHandle version = linker.downcallHandle(symbols.findOrThrow("ocb_abi_version"),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT));
            if ((int) version.invokeExact() != 1) {
                throw new IllegalStateException("unsupported Open Crate FFI ABI");
            }
            MethodHandle generate = linker.downcallHandle(symbols.findOrThrow("ocb_generate_recipient"),
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
            FunctionDescriptor operation = FunctionDescriptor.of(ValueLayout.JAVA_INT,
                    ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS,
                    ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
                    ValueLayout.ADDRESS);
            MethodHandle seal = linker.downcallHandle(symbols.findOrThrow("ocb_seal"), operation);
            MethodHandle open = linker.downcallHandle(symbols.findOrThrow("ocb_open"), operation);

            MemorySegment secret = arena.allocate(32);
            MemorySegment publicKey = arena.allocate(32);
            try {
                check((int) generate.invokeWithArguments(secret, publicKey), "generate");
                byte[] plain = "arbitrary bytes from Java".getBytes(StandardCharsets.UTF_8);
                byte[] purposeBytes = "example.java.v1".getBytes(StandardCharsets.UTF_8);
                byte[] contextBytes = "object-7".getBytes(StandardCharsets.UTF_8);
                MemorySegment purpose = arena.allocateFrom(ValueLayout.JAVA_BYTE, purposeBytes);
                MemorySegment context = arena.allocateFrom(ValueLayout.JAVA_BYTE, contextBytes);
                MemorySegment input = arena.allocateFrom(ValueLayout.JAVA_BYTE, plain);
                MemorySegment envelope = arena.allocate(plain.length + 77);
                MemorySegment written = arena.allocate(ValueLayout.JAVA_LONG);
                check((int) seal.invokeWithArguments(publicKey, purpose, (long) purposeBytes.length,
                        context, (long) contextBytes.length, input, (long) plain.length,
                        envelope, envelope.byteSize(), written), "seal");
                long envelopeLen = written.get(ValueLayout.JAVA_LONG, 0);
                MemorySegment opened = arena.allocate(plain.length);
                check((int) open.invokeWithArguments(secret, purpose, (long) purposeBytes.length,
                        context, (long) contextBytes.length, envelope, envelopeLen,
                        opened, opened.byteSize(), written), "open");
                byte[] result = opened.asSlice(0, written.get(ValueLayout.JAVA_LONG, 0))
                        .toArray(ValueLayout.JAVA_BYTE);
                if (!Arrays.equals(result, plain)) {
                    throw new IllegalStateException("round trip mismatch");
                }
                byte[] wrongBytes = "object-8".getBytes(StandardCharsets.UTF_8);
                MemorySegment wrong = arena.allocateFrom(ValueLayout.JAVA_BYTE, wrongBytes);
                int rejected = (int) open.invokeWithArguments(secret, purpose, (long) purposeBytes.length,
                        wrong, (long) wrongBytes.length, envelope, envelopeLen,
                        opened, opened.byteSize(), written);
                if (rejected != CRYPTO) {
                    throw new IllegalStateException("changed context was accepted: " + rejected);
                }
                System.out.println("Java round trip and context rejection passed");
            } finally {
                secret.fill((byte) 0);
            }
        }
    }
}
