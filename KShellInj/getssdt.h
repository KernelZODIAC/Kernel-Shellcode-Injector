#pragma once

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation = 0xb,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation = 0x23,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformationObsolete,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation = 0x4c,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    SystemThreadPriorityClientIdInformation,
    SystemProcessorIdleCycleTimeInformation,
    SystemVerifierCancellationInformation,
    SystemProcessorPowerInformationEx,
    SystemRefTraceInformation,
    SystemSpecialPoolInformation,
    SystemProcessIdInformation,
    SystemErrorPortInformation,
    SystemBootEnvironmentInformation,
    SystemHypervisorInformation,
    SystemVerifierInformationEx,
    SystemTimeZoneInformation,
    SystemImageFileExecutionOptionsInformation,
    SystemCoverageInformation,
    SystemPrefetchPatchInformation,
    SystemVerifierFaultsInformation,
    SystemSystemPartitionInformation,
    SystemSystemDiskInformation,
    SystemProcessorPerformanceDistribution,
    SystemNumaProximityNodeInformation,
    SystemDynamicTimeZoneInformation,
    SystemCodeIntegrityInformation,
    SystemProcessorMicrocodeUpdateInformation,
    SystemProcessorBrandString,
    SystemVirtualAddressInformation,
    SystemLogicalProcessorAndGroupInformation,
    SystemProcessorCycleTimeInformation,
    SystemStoreInformation,
    SystemRegistryAppendString,
    SystemAitSamplingValue,
    SystemVhdBootInformation,
    SystemCpuQuotaInformation,
    SystemNativeBasicInformation,
    SystemSpare1,
    SystemLowPriorityIoInformation,
    SystemTpmBootEntropyInformation,
    SystemVerifierCountersInformation,
    SystemPagedPoolInformationEx,
    SystemSystemPtesInformationEx,
    SystemNodeDistanceInformation,
    SystemAcpiAuditInformation,
    SystemBasicPerformanceInformation,
    SystemQueryPerformanceCounterInformation,
    SystemSessionBigPoolInformation,
    SystemBootGraphicsInformation,
    SystemScrubPhysicalMemoryInformation,
    SystemBadPageInformation,
    SystemProcessorProfileControlArea,
    SystemCombinePhysicalMemoryInformation,
    SystemEntropyInterruptTimingCallback,
    SystemConsoleInformation,
    SystemPlatformBinaryInformation,
    SystemThrottleNotificationInformation,
    SystemHypervisorProcessorCountInformation,
    SystemDeviceDataInformation,
    SystemDeviceDataEnumerationInformation,
    SystemMemoryTopologyInformation,
    SystemMemoryChannelInformation,
    SystemBootLogoInformation,
    SystemProcessorPerformanceInformationEx,
    SystemSpare0,
    SystemSecureBootPolicyInformation,
    SystemPageFileInformationEx,
    SystemSecureBootInformation,
    SystemEntropyInterruptTimingRawInformation,
    SystemPortableWorkspaceEfiLauncherInformation,
    SystemFullProcessInformation,
    SystemKernelDebuggerInformationEx,
    SystemBootMetadataInformation,
    SystemSoftRebootInformation,
    SystemElamCertificateInformation,
    SystemOfflineDumpConfigInformation,
    SystemProcessorFeaturesInformation,
    SystemRegistryReconciliationInformation,
    SystemEdidInformation,
    SystemManufacturingInformation,
    SystemEnergyEstimationConfigInformation,
    SystemHypervisorDetailInformation,
    SystemProcessorCycleStatsInformation,
    SystemVmGenerationCountInformation,
    SystemTrustedPlatformModuleInformation,
    SystemKernelDebuggerFlags,
    SystemCodeIntegrityPolicyInformation,
    SystemIsolatedUserModeInformation,
    SystemHardwareSecurityTestInterfaceResultsInformation,
    SystemSingleModuleInformation,
    SystemAllowedCpuSetsInformation,
    SystemDmaProtectionInformation,
    SystemInterruptCpuSetsInformation,
    SystemSecureBootPolicyFullInformation,
    SystemCodeIntegrityPolicyFullInformation,
    SystemAffinitizedInterruptProcessorInformation,
    SystemRootSiloInformation,
    SystemCpuSetInformation,
    SystemCpuSetTagInformation,
    SystemWin32WerStartCallout,
    SystemSecureKernelProfileInformation,
    SystemCodeIntegrityPlatformManifestInformation,
    SystemInterruptSteeringInformation,
    SystemSupportedProcessorArchitectures,
    SystemMemoryUsageInformation,
    SystemCodeIntegrityCertificateInformation,
    SystemPhysicalMemoryInformation,
    SystemControlFlowTransition,
    SystemKernelDebuggingAllowed,
    SystemActivityModerationExeState,
    SystemActivityModerationUserSettings,
    SystemCodeIntegrityPoliciesFullInformation,
    SystemCodeIntegrityUnlockInformation,
    SystemIntegrityQuotaInformation,
    SystemFlushInformation,
    SystemProcessorIdleMaskInformation,
    SystemSecureDumpEncryptionInformation,
    SystemWriteConstraintInformation,
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

extern "C" NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

unsigned char* FileData = 0;
ULONG FileSize = 0;

#define PE_ERROR_VALUE (ULONG)-1
#define RANDOM_SEED_INIT 0x3AF84E05
static ULONG RandomSeed = RANDOM_SEED_INIT;

ULONG RtlNextRandom(ULONG Min, ULONG Max)
{
    if (RandomSeed == RANDOM_SEED_INIT)
        RandomSeed = static_cast<ULONG>(__rdtsc());
    const ULONG Scale = static_cast<ULONG>(MAXINT32) / (Max - Min);
    return RtlRandomEx(&RandomSeed) / Scale + Min;
}

ULONG GetPoolTag()
{
    constexpr ULONG PoolTags[] =
    {
        ' prI',
        '+prI',
        'eliF',
        'atuM',
        'sFtN',
        'ameS',
        'RwtE',
        'nevE',
        ' daV',
        'sdaV',
        'aCmM',
        '  oI',
        'tiaW',
        'eSmM',
        'CPLA',
        'GwtE',
        ' ldM',
        'erhT',
        'cScC',
        'KgxD',
    };
    constexpr ULONG NumPoolTags = ARRAYSIZE(PoolTags);
    const ULONG Index = RtlNextRandom(0, NumPoolTags);
    NT_ASSERT(Index <= NumPoolTags - 1);
    return PoolTags[Index];
}

void* RtlAllocateMemory(bool InZeroMemory, SIZE_T InSize)
{
    void* Result = ExAllocatePoolWithTag(NonPagedPool, InSize, GetPoolTag());
    if (InZeroMemory && (Result != NULL))
        RtlZeroMemory(Result, InSize);
    return Result;
}

void RtlFreeMemory(void* InPointer)
{
    ExFreePool(InPointer);
}

NTSTATUS NTDLL_Initialize()
{
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    RtlInitUnicodeString(&FileName, L"\\SystemRoot\\system32\\ntdll.dll");
    InitializeObjectAttributes(&ObjectAttributes, &FileName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return STATUS_UNSUCCESSFUL;
    }
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS NtStatus = ZwCreateFile(&FileHandle,
        GENERIC_READ,
        &ObjectAttributes,
        &IoStatusBlock, NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    if (NT_SUCCESS(NtStatus))
    {
        FILE_STANDARD_INFORMATION StandardInformation = { 0 };
        NtStatus = ZwQueryInformationFile(FileHandle, &IoStatusBlock, &StandardInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
        if (NT_SUCCESS(NtStatus))
        {
            FileSize = StandardInformation.EndOfFile.LowPart;
            FileData = (unsigned char*)RtlAllocateMemory(true, FileSize);
            LARGE_INTEGER ByteOffset;
            ByteOffset.LowPart = ByteOffset.HighPart = 0;
            NtStatus = ZwReadFile(FileHandle,
                NULL, NULL, NULL,
                &IoStatusBlock,
                FileData,
                FileSize,
                &ByteOffset, NULL);
            if (!NT_SUCCESS(NtStatus))
            {
                RtlFreeMemory(FileData);
            }
        }
        else
            ZwClose(FileHandle);
    }
    return NtStatus;
}

struct SSDTStruct
{
    LONG* pServiceTable;
    PVOID pCounterTable;
#ifdef _WIN64
    ULONGLONG NumberOfServices;
#else
    ULONG NumberOfServices;
#endif
    PCHAR pArgumentTable;
};

extern "C"
NTKERNELAPI
PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(_In_ PVOID Base);

PVOID GetKernelBase(PULONG pImageSize)
{
    typedef struct _SYSTEM_MODULE_ENTRY
    {
        HANDLE Section;
        PVOID MappedBase;
        PVOID ImageBase;
        ULONG ImageSize;
        ULONG Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        UCHAR FullPathName[256];
    } SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

#pragma warning(disable:4200)
    typedef struct _SYSTEM_MODULE_INFORMATION
    {
        ULONG Count;
        SYSTEM_MODULE_ENTRY Module[0];
    } SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

    PVOID pModuleBase = NULL;
    PSYSTEM_MODULE_INFORMATION pSystemInfoBuffer = NULL;
    ULONG SystemInfoBufferSize = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation,
        &SystemInfoBufferSize,
        0,
        &SystemInfoBufferSize);
    if (!SystemInfoBufferSize)
    {
        return NULL;
    }
    pSystemInfoBuffer = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, SystemInfoBufferSize * 2, GetPoolTag());
    if (!pSystemInfoBuffer)
    {
        return NULL;
    }
    memset(pSystemInfoBuffer, 0, SystemInfoBufferSize * 2);
    status = ZwQuerySystemInformation(SystemModuleInformation,
        pSystemInfoBuffer,
        SystemInfoBufferSize * 2,
        &SystemInfoBufferSize);
    if (NT_SUCCESS(status))
    {
        pModuleBase = pSystemInfoBuffer->Module[0].ImageBase;
        if (pImageSize)
            *pImageSize = pSystemInfoBuffer->Module[0].ImageSize;
    }
    ExFreePool(pSystemInfoBuffer);
    return pModuleBase;
}

static SSDTStruct* SSDTfind()
{
    static SSDTStruct* SSDT = 0;
    if (!SSDT)
    {
#ifndef _WIN64
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
        SSDT = (SSDTStruct*)MmGetSystemRoutineAddress(&routineName);
#else
        ULONG kernelSize;
        ULONG_PTR kernelBase = (ULONG_PTR)GetKernelBase(&kernelSize);
        if (kernelBase == 0 || kernelSize == 0)
            return nullptr;
        PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader((PVOID)kernelBase);
        PIMAGE_SECTION_HEADER textSection = nullptr;
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (ULONG i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
        {
            char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
            RtlCopyMemory(sectionName, section->Name, IMAGE_SIZEOF_SHORT_NAME);
            sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
            if (strncmp(sectionName, ".text", sizeof(".text") - sizeof(char)) == 0)
            {
                textSection = section;
                break;
            }
            section++;
        }
        if (textSection == nullptr)
            return nullptr;
        const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
        const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
        bool found = false;
        ULONG KiSSSOffset;
        for (KiSSSOffset = 0; KiSSSOffset < textSection->Misc.VirtualSize - signatureSize; KiSSSOffset++)
        {
            if (RtlCompareMemory(((unsigned char*)kernelBase + textSection->VirtualAddress + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
            {
                found = true;
                break;
            }
        }
        if (!found)
            return nullptr;
        ULONG_PTR address = kernelBase + textSection->VirtualAddress + KiSSSOffset + signatureSize;
        LONG relativeOffset = 0;
        if ((*(unsigned char*)address == 0x4c) &&
            (*(unsigned char*)(address + 1) == 0x8d) &&
            (*(unsigned char*)(address + 2) == 0x15))
        {
            relativeOffset = *(LONG*)(address + 3);
        }
        if (relativeOffset == 0)
            return nullptr;
        SSDT = (SSDTStruct*)(address + relativeOffset + 7);
#endif
    }
    return SSDT;
}

static ULONG RvaToOffset(PIMAGE_NT_HEADERS pnth, ULONG Rva, ULONG FileSize)
{
    PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(pnth);
    USHORT NumberOfSections = pnth->FileHeader.NumberOfSections;
    for (int i = 0; i < NumberOfSections; i++)
    {
        if (psh->VirtualAddress <= Rva)
        {
            if ((psh->VirtualAddress + psh->Misc.VirtualSize) > Rva)
            {
                Rva -= psh->VirtualAddress;
                Rva += psh->PointerToRawData;
                return Rva < FileSize ? Rva : PE_ERROR_VALUE;
            }
        }
        psh++;
    }
    return PE_ERROR_VALUE;
}

ULONG GetExportOffset(const unsigned char* FileData, ULONG FileSize, const char* ExportName)
{
    PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)FileData;
    if (pdh->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return PE_ERROR_VALUE;
    }
    PIMAGE_NT_HEADERS pnth = (PIMAGE_NT_HEADERS)(FileData + pdh->e_lfanew);
    if (pnth->Signature != IMAGE_NT_SIGNATURE)
    {
        return PE_ERROR_VALUE;
    }
    PIMAGE_DATA_DIRECTORY pdd = NULL;
    if (pnth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        pdd = ((PIMAGE_NT_HEADERS64)pnth)->OptionalHeader.DataDirectory;
    else
        pdd = ((PIMAGE_NT_HEADERS32)pnth)->OptionalHeader.DataDirectory;
    ULONG ExportDirRva = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG ExportDirSize = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    ULONG ExportDirOffset = RvaToOffset(pnth, ExportDirRva, FileSize);
    if (ExportDirOffset == PE_ERROR_VALUE)
    {
        return PE_ERROR_VALUE;
    }
    PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)(FileData + ExportDirOffset);
    ULONG NumberOfNames = ExportDir->NumberOfNames;
    ULONG AddressOfFunctionsOffset = RvaToOffset(pnth, ExportDir->AddressOfFunctions, FileSize);
    ULONG AddressOfNameOrdinalsOffset = RvaToOffset(pnth, ExportDir->AddressOfNameOrdinals, FileSize);
    ULONG AddressOfNamesOffset = RvaToOffset(pnth, ExportDir->AddressOfNames, FileSize);
    if (AddressOfFunctionsOffset == PE_ERROR_VALUE ||
        AddressOfNameOrdinalsOffset == PE_ERROR_VALUE ||
        AddressOfNamesOffset == PE_ERROR_VALUE)
    {
        return PE_ERROR_VALUE;
    }
    ULONG* AddressOfFunctions = (ULONG*)(FileData + AddressOfFunctionsOffset);
    USHORT* AddressOfNameOrdinals = (USHORT*)(FileData + AddressOfNameOrdinalsOffset);
    ULONG* AddressOfNames = (ULONG*)(FileData + AddressOfNamesOffset);
    ULONG ExportOffset = PE_ERROR_VALUE;
    for (ULONG i = 0; i < NumberOfNames; i++)
    {
        ULONG CurrentNameOffset = RvaToOffset(pnth, AddressOfNames[i], FileSize);
        if (CurrentNameOffset == PE_ERROR_VALUE)
            continue;
        const char* CurrentName = (const char*)(FileData + CurrentNameOffset);
        ULONG CurrentFunctionRva = AddressOfFunctions[AddressOfNameOrdinals[i]];
        if (CurrentFunctionRva >= ExportDirRva && CurrentFunctionRva < ExportDirRva + ExportDirSize)
            continue;
        if (!strcmp(CurrentName, ExportName))
        {
            ExportOffset = RvaToOffset(pnth, CurrentFunctionRva, FileSize);
            break;
        }
    }
    return ExportOffset;
}

int GetExportSsdtIndex(const char* ExportName)
{
    ULONG_PTR ExportOffset = GetExportOffset(FileData, FileSize, ExportName);
    if (ExportOffset == PE_ERROR_VALUE)
        return -1;
    int SsdtOffset = -1;
    unsigned char* ExportData = FileData + ExportOffset;
    for (int i = 0; i < 32 && ExportOffset + i < FileSize; i++)
    {
        if (ExportData[i] == 0xC2 || ExportData[i] == 0xC3)
            break;
        if (ExportData[i] == 0xB8)
        {
            SsdtOffset = *(int*)(ExportData + i + 1);
            break;
        }
    }
    return SsdtOffset;
}

PVOID GetFunctionAddress(const char* apiname)
{
    SSDTStruct* SSDT = SSDTfind();
    if (!SSDT)
    {
        return 0;
    }
    ULONG_PTR SSDTbase = (ULONG_PTR)SSDT->pServiceTable;
    if (!SSDTbase)
    {
        return 0;
    }
    ULONG readOffset = GetExportSsdtIndex(apiname);
    if (readOffset == -1)
        return 0;
    if (readOffset >= SSDT->NumberOfServices)
    {
        return 0;
    }
#ifdef _WIN64
    return (PVOID)((SSDT->pServiceTable[readOffset] >> 4) + SSDTbase);
#else
    return (PVOID)SSDT->pServiceTable[readOffset];
#endif
}
