#include "msmon.h"

static LARGE_INTEGER gRegistryCookie;
static BOOLEAN gRegistryRegistered;

typedef struct _MSMON_REGISTRY_CONTEXT {
    HANDLE ProcessId;
    HANDLE ThreadId;
    ULONG Type;
    ULONG DesiredAccess;
    ULONGLONG Value0;
    ULONGLONG Value1;
    UNICODE_STRING Path;
    UNICODE_STRING Detail;
} MSMON_REGISTRY_CONTEXT, *PMSMON_REGISTRY_CONTEXT;

static PCUNICODE_STRING MsMonRegistryPath(PVOID Object)
{
    PCUNICODE_STRING name = NULL;
    ULONG_PTR objectId = 0;
    if (NT_SUCCESS(CmCallbackGetKeyObjectID(&gRegistryCookie, Object, &objectId, &name))) return name;
    return NULL;
}

static USHORT MsMonContextStringLength(PCUNICODE_STRING Value)
{
    if (Value == NULL || Value->Buffer == NULL) return 0;
    return min(Value->Length, MSMON_MAX_EVENT_STRING_BYTES);
}

static PMSMON_REGISTRY_CONTEXT MsMonCreateContext(
    ULONG Type,
    PCUNICODE_STRING Path,
    PCUNICODE_STRING Detail,
    ULONGLONG Value0,
    ULONGLONG Value1,
    ULONG DesiredAccess
)
{
    USHORT pathBytes = MsMonContextStringLength(Path);
    USHORT detailBytes = MsMonContextStringLength(Detail);
    SIZE_T size = sizeof(MSMON_REGISTRY_CONTEXT) + pathBytes + detailBytes;
    PMSMON_REGISTRY_CONTEXT context = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, MSMON_POOL_TAG);
    PUCHAR cursor;
    if (context == NULL) return NULL;
    RtlZeroMemory(context, size);
    context->ProcessId = PsGetCurrentProcessId();
    context->ThreadId = PsGetCurrentThreadId();
    context->Type = Type;
    context->DesiredAccess = DesiredAccess;
    context->Value0 = Value0;
    context->Value1 = Value1;
    cursor = (PUCHAR)(context + 1);
    if (pathBytes != 0) {
        RtlCopyMemory(cursor, Path->Buffer, pathBytes);
        context->Path.Buffer = (PWSTR)cursor;
        context->Path.Length = pathBytes;
        context->Path.MaximumLength = pathBytes;
        cursor += pathBytes;
    }
    if (detailBytes != 0) {
        RtlCopyMemory(cursor, Detail->Buffer, detailBytes);
        context->Detail.Buffer = (PWSTR)cursor;
        context->Detail.Length = detailBytes;
        context->Detail.MaximumLength = detailBytes;
    }
    return context;
}

static BOOLEAN MsMonIsPostOperation(REG_NOTIFY_CLASS Operation)
{
    switch (Operation) {
    case RegNtPostDeleteKey:
    case RegNtPostSetValueKey:
    case RegNtPostDeleteValueKey:
    case RegNtPostRenameKey:
    case RegNtPostEnumerateKey:
    case RegNtPostEnumerateValueKey:
    case RegNtPostQueryKey:
    case RegNtPostQueryValueKey:
    case RegNtPostQueryMultipleValueKey:
    case RegNtPostCreateKeyEx:
    case RegNtPostOpenKeyEx:
        return TRUE;
    default:
        return FALSE;
    }
}

static VOID MsMonSetCallContext(REG_NOTIFY_CLASS Operation, PVOID Argument, PVOID Context)
{
    switch (Operation) {
    case RegNtPreOpenKeyEx:
    case RegNtPreCreateKeyEx:
        ((PREG_OPEN_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreSetValueKey:
        ((PREG_SET_VALUE_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreDeleteKey:
        ((PREG_DELETE_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreDeleteValueKey:
        ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreRenameKey:
        ((PREG_RENAME_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreQueryKey:
        ((PREG_QUERY_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreQueryValueKey:
        ((PREG_QUERY_VALUE_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreQueryMultipleValueKey:
        ((PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreEnumerateKey:
        ((PREG_ENUMERATE_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    case RegNtPreEnumerateValueKey:
        ((PREG_ENUMERATE_VALUE_KEY_INFORMATION)Argument)->CallContext = Context;
        break;
    default:
        break;
    }
}

static NTSTATUS MsMonRegistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
    REG_NOTIFY_CLASS operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    PMSMON_REGISTRY_CONTEXT context = NULL;
    PCUNICODE_STRING path = NULL;
    PCUNICODE_STRING detail = NULL;
    ULONG type = MsMonRegistryOpen;
    ULONG desiredAccess = 0;
    ULONGLONG value0 = 0;
    ULONGLONG value1 = 0;

    UNREFERENCED_PARAMETER(CallbackContext);
    if (MsMonIsPostOperation(operation)) {
        PREG_POST_OPERATION_INFORMATION post = (PREG_POST_OPERATION_INFORMATION)Argument2;
        context = (PMSMON_REGISTRY_CONTEXT)post->CallContext;
        if (context == NULL) return STATUS_SUCCESS;
        (VOID)MsMonLogEvent(context->Type, context->ProcessId, NULL, context->ThreadId,
                            NULL, 0, context->Path.Buffer == NULL ? MsMonFlagMissingPath : 0,
                            post->Status, context->DesiredAccess, MsMonCategoryRegistry,
                            context->Value0, context->Value1,
                            context->Path.Buffer != NULL ? &context->Path : NULL,
                            context->Detail.Buffer != NULL ? &context->Detail : NULL);
        ExFreePoolWithTag(context, MSMON_POOL_TAG);
        return STATUS_SUCCESS;
    }
    if (!MsMonIsTracked(PsGetCurrentProcessId(), 0)) return STATUS_SUCCESS;

    switch (operation) {
    case RegNtPreOpenKeyEx:
    case RegNtPreCreateKeyEx: {
        PREG_OPEN_KEY_INFORMATION info = (PREG_OPEN_KEY_INFORMATION)Argument2;
        path = info->CompleteName;
        desiredAccess = info->DesiredAccess;
        type = operation == RegNtPreOpenKeyEx ? MsMonRegistryOpen : MsMonRegistryCreate;
        break;
    }
    case RegNtPreSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        detail = info->ValueName;
        value0 = info->DataSize;
        value1 = info->Type;
        type = MsMonRegistrySetValue;
        break;
    }
    case RegNtPreDeleteKey: {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        type = MsMonRegistryDelete;
        break;
    }
    case RegNtPreDeleteValueKey: {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        detail = info->ValueName;
        type = MsMonRegistryDelete;
        break;
    }
    case RegNtPreRenameKey: {
        PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        detail = info->NewName;
        type = MsMonRegistryRename;
        break;
    }
    case RegNtPreQueryKey: {
        PREG_QUERY_KEY_INFORMATION info = (PREG_QUERY_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        value0 = info->KeyInformationClass;
        type = MsMonRegistryQuery;
        break;
    }
    case RegNtPreQueryValueKey: {
        PREG_QUERY_VALUE_KEY_INFORMATION info = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        detail = info->ValueName;
        value0 = info->KeyValueInformationClass;
        type = MsMonRegistryQuery;
        break;
    }
    case RegNtPreQueryMultipleValueKey: {
        PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION info = (PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        value0 = info->EntryCount;
        type = MsMonRegistryQuery;
        break;
    }
    case RegNtPreEnumerateKey: {
        PREG_ENUMERATE_KEY_INFORMATION info = (PREG_ENUMERATE_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        value0 = info->Index;
        value1 = info->KeyInformationClass;
        type = MsMonRegistryEnumerate;
        break;
    }
    case RegNtPreEnumerateValueKey: {
        PREG_ENUMERATE_VALUE_KEY_INFORMATION info = (PREG_ENUMERATE_VALUE_KEY_INFORMATION)Argument2;
        path = MsMonRegistryPath(info->Object);
        value0 = info->Index;
        value1 = info->KeyValueInformationClass;
        type = MsMonRegistryEnumerate;
        break;
    }
    default:
        return STATUS_SUCCESS;
    }

    context = MsMonCreateContext(type, path, detail, value0, value1, desiredAccess);
    if (context != NULL) MsMonSetCallContext(operation, Argument2, context);
    return STATUS_SUCCESS;
}

NTSTATUS MsMonRegistryInitialize(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING altitude;
    NTSTATUS status;
    RtlInitUnicodeString(&altitude, L"380010");
    status = CmRegisterCallbackEx(MsMonRegistryCallback, &altitude, DriverObject,
                                  NULL, &gRegistryCookie, NULL);
    gRegistryRegistered = NT_SUCCESS(status);
    return status;
}

VOID MsMonRegistryUninitialize(VOID)
{
    if (gRegistryRegistered) {
        (VOID)CmUnRegisterCallback(gRegistryCookie);
        gRegistryRegistered = FALSE;
    }
}
