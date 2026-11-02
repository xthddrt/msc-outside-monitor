$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path
$source = Get-Content (Join-Path $root 'driver\network.c') -Raw

function Body([string] $text, [string] $startMarker, [string] $endMarker, [string] $what) {
    $start = $text.IndexOf($startMarker)
    if ($start -lt 0) { throw "$what not found" }
    $end = $text.IndexOf($endMarker, $start)
    if ($end -lt 0) { throw "$what end not found" }
    return $text.Substring($start, $end - $start)
}

$associate = Body $source 'static VOID MsMonAssociateFlow(' 'static VOID NTAPI MsMonWfpClassifyInner(' 'MsMonAssociateFlow'
$insert = $associate.IndexOf('InsertTailList(&gFlows')
$association = $associate.IndexOf('FwpsFlowAssociateContext0(')
$remove = $associate.IndexOf('FwpsFlowRemoveContext0(')
if ($insert -lt 0 -or $association -lt $insert -or $remove -lt $association) {
    throw 'MsMonAssociateFlow does not publish before association and retain inactive removal'
}
if ($associate.Contains('(VOID)FwpsFlowRemoveContext0')) {
    throw 'MsMonAssociateFlow still discards the removal result'
}
if ($associate.Contains('KeDelayExecutionThread')) {
    throw 'MsMonAssociateFlow must not wait in the WFP classify path'
}

# The association key and ownership state must be fixed before publication.
$afterLink = $associate.Substring($insert)
foreach ($field in 'FlowId', 'LayerId', 'CalloutId') {
    if ($afterLink.Contains("context->$field")) {
        throw "context->$field is read after the context is linked"
    }
}
if (-not $associate.Contains('flowId = FlowId') -or
    -not $associate.Contains('layerId = InFixedValues->layerId') -or
    -not $associate.Contains('calloutId = gCalloutIds[Index]') -or
    -not $associate.Contains('FwpsFlowAssociateContext0(flowId, layerId, calloutId,') -or
    -not $associate.Contains('FwpsFlowRemoveContext0(flowId, layerId, calloutId)')) {
    throw 'MsMonAssociateFlow does not use captured association keys'
}
$associating = $associate.IndexOf('context->Associating = TRUE')
$associated = $associate.IndexOf('context->Associating = FALSE')
$deleted = $associate.IndexOf('deleted = context->Deleted')
if ($associating -lt 0 -or $associating -gt $insert -or
    $associated -lt $association -or $deleted -lt $associated) {
    throw 'association ownership is not tracked across the callback window'
}
if (-not $associate.Contains('if (!NT_SUCCESS(status) && !deleted) RemoveEntryList(&context->Link);') -or
    -not $associate.Contains('if (deleted)') -or
    $associate.IndexOf('if (deleted)') -gt $remove) {
    throw 'association failure or early deletion does not leave a single owner'
}

# Freeing after a completed inactive removal is only for the "no association" result,
# and only through an unlink keyed on the flow id.
$unlink = $associate.IndexOf('MsMonFlowUnlink(flowId)')
if ($unlink -lt 0) { throw 'MsMonAssociateFlow does not unlink by the captured flow id' }
$noAssociation = $associate.IndexOf('0xC0000001')
if ($noAssociation -lt 0 -or $unlink -lt $noAssociation) {
    throw 'the unlink/free is not restricted to the no-association result'
}
$free = $associate.IndexOf('ExFreePoolWithTag(context', $unlink)
if ($free -lt 0 -or $free -lt $unlink) { throw 'ExFreePoolWithTag runs before the unlink decides ownership' }

$delete = Body $source 'static VOID NTAPI MsMonWfpFlowDeleteInner(' 'static VOID NTAPI MsMonWfpFlowDelete(' 'MsMonWfpFlowDeleteInner'
$pending = $delete.IndexOf('if (candidate->Associating)')
$pendingEnd = $delete.IndexOf('} else {', $pending)
if ($pending -lt 0 -or $pendingEnd -lt $pending -or
    -not $delete.Contains('candidate->Deleted = TRUE')) {
    throw 'flow deletion does not defer an associating context to its owner'
}
$pendingBody = $delete.Substring($pending, $pendingEnd - $pending)
if ($pendingBody.Contains('ExFreePoolWithTag') -or $pendingBody.Contains('MsMonLogNetwork')) {
    throw 'flow deletion frees or logs a context the associate thread still owns'
}

# A passive monitor must never override another filter with a permit.
if ($source.Contains('FWP_ACTION_PERMIT')) {
    throw 'the passive monitor still issues FWP_ACTION_PERMIT'
}
$inner = Body $source 'static VOID NTAPI MsMonWfpClassifyInner(' 'static VOID NTAPI MsMonWfpClassify(' 'MsMonWfpClassifyInner'
$outer = Body $source 'static VOID NTAPI MsMonWfpClassify(' 'static NTSTATUS NTAPI MsMonWfpNotify(' 'MsMonWfpClassify'
foreach ($body in @($inner, $outer)) {
    if (-not $body.Contains('ClassifyOut->actionType = FWP_ACTION_CONTINUE;')) {
        throw 'a classify path does not continue the filter decision'
    }
}

$helper = Body $source 'static BOOLEAN MsMonFlowUnlink(' 'static VOID MsMonAssociateFlow(' 'MsMonFlowUnlink'
if (-not $helper.Contains('candidate->FlowId == FlowId')) {
    throw 'MsMonFlowUnlink does not match the captured flow id'
}

$unloadStart = $source.IndexOf('VOID MsMonNetworkUninitialize(')
if ($unloadStart -lt 0) { throw 'MsMonNetworkUninitialize not found' }
$unload = $source.Substring($unloadStart)
$wait = $unload.IndexOf('ExWaitForRundownProtectionRelease(&gNetworkRundown)')
$drain = $unload.IndexOf('RemoveHeadList(&gFlows)')
$complete = $unload.IndexOf('ExRundownCompleted(&gNetworkRundown)')
if ($wait -lt 0 -or $drain -lt 0 -or $complete -lt 0) {
    throw 'MsMonNetworkUninitialize lost its rundown wait, drain or completion'
}
if ($wait -gt $drain) { throw 'the flow-list drain runs before the rundown wait' }
if ($complete -lt $drain) { throw 'the rundown is completed before the flow-list drain' }
if ($unload.Substring(0, $wait).IndexOf('if (gNetworkRundownInitialized)') -lt 0) {
    throw 'the rundown wait is no longer guarded for the load-failure cleanup path'
}

Write-Host 'flow owner source regression passed'
