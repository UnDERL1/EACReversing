char ScanProcessWorkingSet(__int64 process, char previousMode, WORKINGSET_DETECTION_BUFFER** outDetectionBuffer)
{
    if (!outDetectionBuffer) return 0;
    *outDetectionBuffer = nullptr;
    MEMORY_WORKING_SET_INFORMATION* wsi = (MEMORY_WORKING_SET_INFORMATION*)AllocatePool(0x100000i64);
    if (!wsi) return 0;
    if (!QueryVirtualMemory0(0i64, process, 1u, (__int64)wsi, previousMode, 0x100000i64)) goto CLEANUP;
    WORKINGSET_DETECTION_BUFFER* detectionBuffer = (WORKINGSET_DETECTION_BUFFER*)AllocatePool(2048i64);
    if (!detectionBuffer) goto CLEANUP;
    memset(detectionBuffer, 0, 2048ui64);
    detectionBuffer->usedBytes = 16;
    detectionBuffer->maxSize = 2048;
    *outDetectionBuffer = detectionBuffer;
    ULONG_PTR v12 = 0i64;
    int* info = (int*)wsi->WorkingSetInfo;
    while (v12 < wsi->NumberOfEntries) {
        unsigned __int64 protection = *(_QWORD*)info & 0x1Fi64;
        if (protection > 19 || (protection == 22) || (protection == 30) || (protection == 31)) {
            if (previousMode && !_bittest64((const signed __int64*)info, 8u)) {
                CheckWorkingSetEntry(*outDetectionBuffer, info, previousMode);
                return 1;
            }
        }
        ++v12;
        info += 2;
    }
CLEANUP:
    if (*outDetectionBuffer) FreePool((__int64)*outDetectionBuffer);
    FreePool((__int64)wsi);
    return 0;
}

char CheckWorkingSetEntry(WORKINGSET_DETECTION_BUFFER* detectionBuffer, int* pWsiInfo, signed int previousMode)
{
    if (!detectionBuffer) return 0;
    if (detectionBuffer->maxSize < 0x10) return 0;
    if (detectionBuffer->maxSize - detectionBuffer->usedBytes < 33) return 0;

    void* address = (void*)(*pWsiInfo & 0xFFFFFFFFFFFFF000ui64);
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    mbi.BaseAddress = address;

    if (QueryVirtualMemory((__int64)address, -1i64, 0, (__int64)&mbi, previousMode, 48i64, 0i64) < 0) {
        WORKINGSET_DETECTION_ENTRY detectionEntry = { 0 };
        detectionEntry.address = (__int64)address;
        detectionEntry.isShared = (*pWsiInfo & 0x100i64) != 0;
        detectionEntry.protection = *pWsiInfo & 0x1F;
        detectionBuffer->entries[detectionBuffer->count] = detectionEntry;
        detectionBuffer->count++;
        detectionBuffer->usedBytes += 33;
        return 1;
    }

    for (unsigned int i = 0; i < detectionBuffer->count; i++) {
        if (detectionBuffer->entries[i].address == (__int64)mbi.AllocationBase) {
            return 0;
        }
    }

    WORKINGSET_DETECTION_ENTRY detectionEntry = { 0 };
    detectionEntry.address = (__int64)mbi.AllocationBase;
    detectionEntry.offsetFromAllocationBase = (_DWORD)address - LODWORD(mbi.AllocationBase);
    if (GetMappedFilename(-1i64, (__int64)mbi.AllocationBase, (__int64)&detectionEntry.mappedFilename, previousMode)) {
        UNICODE_STRING string;
        if (sub_289F0(&detectionEntry.mappedFilename.Length, (__int64)&string)) {
            CopyUnicodeStringToAnsiBuffer((__int64)detectionEntry.mappedFilename, 16i64, &string);
        }
        FreeUnicodeString(&detectionEntry.mappedFilename);
    }
    detectionEntry.isShared = (*pWsiInfo & 0x100i64) != 0;
    detectionEntry.protection = *pWsiInfo & 0x1F;
    detectionBuffer->entries[detectionBuffer->count] = detectionEntry;
    detectionBuffer->count++;
    detectionBuffer->usedBytes += 33;
    return 1;
}
