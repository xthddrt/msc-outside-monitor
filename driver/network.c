#include <ntddk.h>
#pragma warning(push)
#pragma warning(disable:4201)
#define NDIS630 1
#include <ndis.h>
#pragma warning(pop)
#include <fwpsk.h>
#include <fwpmk.h>
#include <ntstrsafe.h>
#include "../include/msmon_protocol.h"

#define MSMON_POOL_TAG 'noSM'
#define MSMON_CALLOUT_COUNT 6

BOOLEAN MsMonIsTracked(HANDLE ProcessId, LONGLONG StartTime);
NTSTATUS MsMonLogEvent(ULONG Type, HANDLE ProcessId, HANDLE ParentProcessId, HANDLE ThreadId,
                       HANDLE TargetProcessId, LONGLONG TargetProcessStartTime, ULONG Flags,
                       NTSTATUS Status, ULONG DesiredAccess, ULONG Category,
                       ULONGLONG Value0, ULONGLONG Value1,
                       PCUNICODE_STRING Text, PCUNICODE_STRING Detail);
VOID MsMonNetworkUninitialize(VOID);

static const GUID MSMON_CALLOUT_KEYS[MSMON_CALLOUT_COUNT] = {
    { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x01 } },
    { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x02 } },
    { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x03 } },
    { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x04 } },
    { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x05 } },
    { 0x43f00e61, 0x2a6f, 0x4dd3, { 0x91, 0x3b, 0x1b, 0x42, 0x8c, 0x83, 0x20, 0x06 } }
};

typedef struct _MSMON_FLOW_CONTEXT {
    LIST_ENTRY Link;
    UINT64 FlowId;
    UINT32 CalloutId;
    UINT16 LayerId;
    HANDLE ProcessId;
    UINT8 Protocol;
    UINT16 LocalPort;
    UINT16 RemotePort;
    WCHAR Endpoints[128];
} MSMON_FLOW_CONTEXT, *PMSMON_FLOW_CONTEXT;

static HANDLE gEngine;
static UINT32 gCalloutIds[MSMON_CALLOUT_COUNT];
static BOOLEAN gCalloutRegistered[MSMON_CALLOUT_COUNT];
static LIST_ENTRY gFlows;
static KSPIN_LOCK gFlowLock;
static BOOLEAN gFlowListInitialized;
static BOOLEAN gNetworkActive;
static ULONG gNetworkLayerMask;
static NTSTATUS gNetworkLayerStatus[MSMON_CALLOUT_COUNT];

static VOID NTAPI MsMonWfpFlowDelete(UINT16 LayerId, UINT32 CalloutId, UINT64 FlowContext);

static VOID MsMonFormatIpv4(UINT32 Address, PWSTR Output, SIZE_T Characters)
{
    (VOID)RtlStringCchPrintfW(Output, Characters, L"%u.%u.%u.%u",
                              Address & 0xff, (Address >> 8) & 0xff,
                              (Address >> 16) & 0xff, (Address >> 24) & 0xff);
}

static VOID MsMonFormatIpv6(const FWP_BYTE_ARRAY16* Address, PWSTR Output, SIZE_T Characters)
{
    static const WCHAR hex[] = L"0123456789abcdef";
    ULONG index;
    ULONG offset = 0;
    if (Address == NULL || Characters < 40) {
        if (Characters != 0) Output[0] = L'\0';
        return;
    }
    for (index = 0; index < 16; index++) {
        Output[offset++] = hex[Address->byteArray16[index] >> 4];
        Output[offset++] = hex[Address->byteArray16[index] & 0xf];
        if ((index & 1) == 1 && index != 15) Output[offset++] = L':';
    }
    Output[offset] = L'\0';
}

static ULONG MsMonCalloutIndex(const FWPS_FILTER3* Filter)
{
    ULONG index;
    for (index = 0; index < MSMON_CALLOUT_COUNT; index++) {
        if (gCalloutRegistered[index] && Filter->action.calloutId == gCalloutIds[index]) return index;
    }
    return MSMON_CALLOUT_COUNT;
}

static VOID MsMonSelectFields(
    ULONG Index,
    PUINT16 LocalAddress,
    PUINT16 RemoteAddress,
    PUINT16 LocalPort,
    PUINT16 RemotePort,
    PUINT16 Protocol
)
{
    BOOLEAN ipv6 = (Index & 1) != 0;
    if (Index >= 4) {
        if (ipv6) {
            *LocalAddress = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS;
            *RemoteAddress = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS;
            *LocalPort = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT;
            *RemotePort = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT;
            *Protocol = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL;
        } else {
            *LocalAddress = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS;
            *RemoteAddress = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS;
            *LocalPort = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT;
            *RemotePort = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT;
            *Protocol = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL;
        }
    } else if (Index >= 2) {
        if (ipv6) {
            *LocalAddress = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS;
            *RemoteAddress = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS;
            *LocalPort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT;
            *RemotePort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT;
            *Protocol = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL;
        } else {
            *LocalAddress = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS;
            *RemoteAddress = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS;
            *LocalPort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT;
            *RemotePort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT;
            *Protocol = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL;
        }
    } else {
        if (ipv6) {
            *LocalAddress = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS;
            *RemoteAddress = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
            *LocalPort = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT;
            *RemotePort = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
            *Protocol = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
        } else {
            *LocalAddress = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
            *RemoteAddress = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
            *LocalPort = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT;
            *RemotePort = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
            *Protocol = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
        }
    }
}

static VOID MsMonLogNetwork(
    ULONG Type,
    HANDLE ProcessId,
    UINT64 FlowId,
    UINT8 Protocol,
    UINT16 LocalPort,
    UINT16 RemotePort,
    PCWSTR Endpoints,
    PCWSTR Direction
)
{
    UNICODE_STRING text;
    UNICODE_STRING detail;
    ULONGLONG packed = ((ULONGLONG)Protocol << 32) | ((ULONGLONG)LocalPort << 16) | RemotePort;
    RtlInitUnicodeString(&text, Endpoints);
    RtlInitUnicodeString(&detail, Direction);
    (VOID)MsMonLogEvent(Type, ProcessId, NULL, NULL, NULL, 0, 0, STATUS_SUCCESS, 0,
                        MsMonCategoryNetwork, FlowId, packed, &text, &detail);
}

static VOID MsMonAssociateFlow(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    ULONG Index,
    UINT64 FlowId,
    UINT8 Protocol,
    UINT16 LocalPort,
    UINT16 RemotePort,
    PCWSTR Endpoints
)
{
    PMSMON_FLOW_CONTEXT context;
    KIRQL oldIrql;
    NTSTATUS status;
    if (!gFlowListInitialized || (InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) == 0 ||
        FlowId == 0) return;
    context = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*context), MSMON_POOL_TAG);
    if (context == NULL) return;
    RtlZeroMemory(context, sizeof(*context));
    context->FlowId = FlowId;
    context->CalloutId = gCalloutIds[Index];
    context->LayerId = InFixedValues->layerId;
    context->ProcessId = UlongToHandle((ULONG)InMetaValues->processId);
    context->Protocol = Protocol;
    context->LocalPort = LocalPort;
    context->RemotePort = RemotePort;
    (VOID)RtlStringCchCopyW(context->Endpoints, RTL_NUMBER_OF(context->Endpoints), Endpoints);

    /*
     * WFP is called without holding gFlowLock. Holding a spinlock across
     * FwpsFlowAssociateContext0 risks a lock-order inversion with the flow
     * teardown path, which calls MsMonWfpFlowDelete and takes the same lock.
     */
    status = FwpsFlowAssociateContext0(FlowId, InFixedValues->layerId,
                                       gCalloutIds[Index], (UINT64)context);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(context, MSMON_POOL_TAG);
        return;
    }

    KeAcquireSpinLock(&gFlowLock, &oldIrql);
    if (!gNetworkActive) {
        KeReleaseSpinLock(&gFlowLock, oldIrql);
        (VOID)FwpsFlowRemoveContext0(context->FlowId, context->LayerId, context->CalloutId);
        ExFreePoolWithTag(context, MSMON_POOL_TAG);
        return;
    }
    InsertTailList(&gFlows, &context->Link);
    KeReleaseSpinLock(&gFlowLock, oldIrql);
}

static VOID NTAPI MsMonWfpClassify(
    const FWPS_INCOMING_VALUES0* InFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    void* LayerData,
    const void* ClassifyContext,
    const FWPS_FILTER3* Filter,
    UINT64 FlowContext,
    FWPS_CLASSIFY_OUT0* ClassifyOut
)
{
    ULONG index;
    UINT16 localAddressField;
    UINT16 remoteAddressField;
    UINT16 localPortField;
    UINT16 remotePortField;
    UINT16 protocolField;
    UINT16 localPort;
    UINT16 remotePort;
    UINT8 protocol;
    UINT64 flowId = 0;
    WCHAR local[48];
    WCHAR remote[48];
    WCHAR endpoints[128];
    PCWSTR direction;
    ULONG type;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(FlowContext);
    if (ClassifyOut == NULL) return;
    index = Filter != NULL ? MsMonCalloutIndex(Filter) : MSMON_CALLOUT_COUNT;
    do {
        if (index >= MSMON_CALLOUT_COUNT || InFixedValues == NULL || InMetaValues == NULL) break;
        if ((InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) == 0) break;
        if (!MsMonIsTracked(UlongToHandle((ULONG)InMetaValues->processId), 0)) break;
        MsMonSelectFields(index, &localAddressField, &remoteAddressField,
                          &localPortField, &remotePortField, &protocolField);
        /*
         * Never index the layer's value array past the count the filter engine
         * supplied; a layer that reports fewer fields would otherwise make the
         * callout read out of bounds.
         */
        if (protocolField >= InFixedValues->valueCount ||
            localAddressField >= InFixedValues->valueCount ||
            remoteAddressField >= InFixedValues->valueCount ||
            localPortField >= InFixedValues->valueCount ||
            remotePortField >= InFixedValues->valueCount) break;
        localPort = RtlUshortByteSwap(InFixedValues->incomingValue[localPortField].value.uint16);
        remotePort = RtlUshortByteSwap(InFixedValues->incomingValue[remotePortField].value.uint16);
        protocol = InFixedValues->incomingValue[protocolField].value.uint8;
        if ((InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE) != 0) {
            flowId = InMetaValues->flowHandle;
        }
        if ((index & 1) != 0) {
            MsMonFormatIpv6(InFixedValues->incomingValue[localAddressField].value.byteArray16,
                            local, RTL_NUMBER_OF(local));
            MsMonFormatIpv6(InFixedValues->incomingValue[remoteAddressField].value.byteArray16,
                            remote, RTL_NUMBER_OF(remote));
        } else {
            MsMonFormatIpv4(InFixedValues->incomingValue[localAddressField].value.uint32,
                            local, RTL_NUMBER_OF(local));
            MsMonFormatIpv4(InFixedValues->incomingValue[remoteAddressField].value.uint32,
                            remote, RTL_NUMBER_OF(remote));
        }
        (VOID)RtlStringCchPrintfW(endpoints, RTL_NUMBER_OF(endpoints), L"%ws:%u -> %ws:%u",
                                  local, localPort, remote, remotePort);
        if (index >= 4) {
            type = MsMonNetworkFlowEstablished;
            direction = L"flow_established";
        } else if (index >= 2) {
            type = MsMonNetworkAccept;
            direction = L"recv_accept";
        } else {
            type = MsMonNetworkConnect;
            direction = L"connect";
        }
        MsMonLogNetwork(type, UlongToHandle((ULONG)InMetaValues->processId), flowId,
                        protocol, localPort, remotePort, endpoints, direction);
        if (index >= 4 && FlowContext == 0) {
            MsMonAssociateFlow(InFixedValues, InMetaValues, index, flowId,
                               protocol, localPort, remotePort, endpoints);
        }
    } while (0);
    if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
    }
}

static NTSTATUS NTAPI MsMonWfpNotify(
    FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    const GUID* FilterKey,
    const FWPS_FILTER3* Filter
)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);
    return STATUS_SUCCESS;
}

static VOID NTAPI MsMonWfpFlowDelete(UINT16 LayerId, UINT32 CalloutId, UINT64 FlowContext)
{
    PLIST_ENTRY link;
    PMSMON_FLOW_CONTEXT context = NULL;
    KIRQL oldIrql;
    UNREFERENCED_PARAMETER(LayerId);
    UNREFERENCED_PARAMETER(CalloutId);
    if (!gFlowListInitialized || FlowContext == 0) return;
    KeAcquireSpinLock(&gFlowLock, &oldIrql);
    for (link = gFlows.Flink; link != &gFlows; link = link->Flink) {
        PMSMON_FLOW_CONTEXT candidate = CONTAINING_RECORD(link, MSMON_FLOW_CONTEXT, Link);
        if ((UINT64)candidate == FlowContext) {
            RemoveEntryList(&candidate->Link);
            context = candidate;
            break;
        }
    }
    KeReleaseSpinLock(&gFlowLock, oldIrql);
    if (context != NULL) {
        MsMonLogNetwork(MsMonNetworkFlowClose, context->ProcessId, context->FlowId,
                        context->Protocol, context->LocalPort, context->RemotePort,
                        context->Endpoints, L"flow_close");
        ExFreePoolWithTag(context, MSMON_POOL_TAG);
    }
}

static NTSTATUS MsMonAddCallout(
    PDEVICE_OBJECT DeviceObject,
    ULONG Index,
    const GUID* LayerKey,
    PCWSTR Name
)
{
    FWPS_CALLOUT3 callout;
    FWPM_CALLOUT managerCallout;
    FWPM_FILTER filter;
    NTSTATUS status;

    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = MSMON_CALLOUT_KEYS[Index];
    callout.classifyFn = MsMonWfpClassify;
    callout.notifyFn = MsMonWfpNotify;
    if (Index >= 4) callout.flowDeleteFn = MsMonWfpFlowDelete;
    status = FwpsCalloutRegister3(DeviceObject, &callout, &gCalloutIds[Index]);
    if (!NT_SUCCESS(status)) return status;
    gCalloutRegistered[Index] = TRUE;

    RtlZeroMemory(&managerCallout, sizeof(managerCallout));
    managerCallout.calloutKey = MSMON_CALLOUT_KEYS[Index];
    managerCallout.displayData.name = (PWSTR)Name;
    managerCallout.displayData.description = (PWSTR)L"MapleStory application network metadata monitor";
    managerCallout.calloutId = gCalloutIds[Index];
    status = FwpmCalloutAdd(gEngine, &managerCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) return status;

    RtlZeroMemory(&filter, sizeof(filter));
    filter.displayData.name = (PWSTR)Name;
    filter.displayData.description = (PWSTR)L"Observe application network authorization and flow events";
    filter.layerKey = *LayerKey;
    filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = MSMON_CALLOUT_KEYS[Index];
    filter.weight.type = FWP_EMPTY;
    return FwpmFilterAdd(gEngine, &filter, NULL, NULL);
}

NTSTATUS MsMonNetworkInitialize(PDEVICE_OBJECT DeviceObject)
{
    const GUID* layers[MSMON_CALLOUT_COUNT] = {
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
        &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6
    };
    PCWSTR names[MSMON_CALLOUT_COUNT] = {
        L"MsMon connect IPv4", L"MsMon connect IPv6",
        L"MsMon accept IPv4", L"MsMon accept IPv6",
        L"MsMon flow IPv4", L"MsMon flow IPv6"
    };
    FWPM_SESSION session;
    NTSTATUS status;
    ULONG index;
    KeInitializeSpinLock(&gFlowLock);
    InitializeListHead(&gFlows);
    gFlowListInitialized = TRUE;
    gNetworkActive = FALSE;
    gNetworkLayerMask = 0;

    RtlZeroMemory(&session, sizeof(session));
    session.displayData.name = (PWSTR)L"MsMon dynamic session";
    session.displayData.description = (PWSTR)L"Passive application network monitoring";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &gEngine);
    if (!NT_SUCCESS(status)) return status;

    for (index = 0; index < MSMON_CALLOUT_COUNT; index++) {
        status = MsMonAddCallout(DeviceObject, index, layers[index], names[index]);
        gNetworkLayerStatus[index] = status;
        if (NT_SUCCESS(status)) {
            gNetworkLayerMask |= 1u << index;
        } else {
            DbgPrint("MsMon: WFP layer %lu initialization failed 0x%08X\n", index, status);
        }
    }
    gNetworkActive = gNetworkLayerMask != 0;
    return STATUS_SUCCESS;
}

BOOLEAN MsMonNetworkAvailable(VOID)
{
    return gNetworkActive;
}

ULONG MsMonNetworkCoverage(VOID)
{
    return gNetworkLayerMask;
}

VOID MsMonNetworkUninitialize(VOID)
{
    ULONG index;
    KIRQL oldIrql;
    gNetworkActive = FALSE;
    /*
     * Remove flow contexts while the callouts and the engine are still alive,
     * otherwise FwpsFlowRemoveContext0 fails and the flow-delete callback can
     * still fire for a context this routine already freed.
     */
    if (gFlowListInitialized) {
        for (;;) {
            PMSMON_FLOW_CONTEXT context = NULL;
            KeAcquireSpinLock(&gFlowLock, &oldIrql);
            if (!IsListEmpty(&gFlows)) {
                PLIST_ENTRY entry = RemoveHeadList(&gFlows);
                context = CONTAINING_RECORD(entry, MSMON_FLOW_CONTEXT, Link);
            }
            KeReleaseSpinLock(&gFlowLock, oldIrql);
            if (context == NULL) break;
            (VOID)FwpsFlowRemoveContext0(context->FlowId, context->LayerId, context->CalloutId);
            MsMonLogNetwork(MsMonNetworkFlowClose, context->ProcessId, context->FlowId,
                            context->Protocol, context->LocalPort, context->RemotePort,
                            context->Endpoints, L"flow_close_monitor_stop");
            ExFreePoolWithTag(context, MSMON_POOL_TAG);
        }
        gFlowListInitialized = FALSE;
    }
    if (gEngine != NULL) {
        (VOID)FwpmEngineClose(gEngine);
        gEngine = NULL;
    }
    for (index = 0; index < MSMON_CALLOUT_COUNT; index++) {
        if (gCalloutRegistered[index]) {
            /*
             * Only clear the registered flag when the callout really went away.
             * Leaving a registered callout behind after the driver image is
             * unmapped faults the next time traffic hits that layer.
             */
            NTSTATUS status = FwpsCalloutUnregisterById0(gCalloutIds[index]);
            if (NT_SUCCESS(status)) {
                gCalloutRegistered[index] = FALSE;
            } else {
                DbgPrint("MsMon: WFP callout %lu unregister failed 0x%08X\n", index, status);
            }
        }
        gNetworkLayerStatus[index] = STATUS_SUCCESS;
    }
    gNetworkLayerMask = 0;
}
