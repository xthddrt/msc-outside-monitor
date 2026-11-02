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
$remove = $associate.IndexOf('FwpsFlowRemoveContext0(')
if ($insert -lt 0 -or $remove -lt 0 -or $insert -gt $remove) {
    throw 'MsMonAssociateFlow does not link the context before asking WFP to remove it'
}
if ($associate.Contains('(VOID)FwpsFlowRemoveContext0')) {
    throw 'MsMonAssociateFlow still discards the removal result'
}
if ($associate.Contains('KeDelayExecutionThread')) {
    throw 'MsMonAssociateFlow must not wait in the WFP classify path'
}

# The association key must be captured before the context becomes callback-visible,
# and the removal call must use those locals.
$afterLink = $associate.Substring($insert)
foreach ($field in 'FlowId', 'LayerId', 'CalloutId') {
    if ($afterLink.Contains("context->$field")) {
        throw "context->$field is read after the context is linked"
    }
}
if (-not $associate.Contains('flowId = context->FlowId') -or
    -not $associate.Contains('FwpsFlowRemoveContext0(flowId, layerId, calloutId)')) {
    throw 'MsMonAssociateFlow does not call FwpsFlowRemoveContext0 with the captured key'
}

# Freeing is only for the "no association was present" result, and only through an
# unlink keyed on the flow id.
$unlink = $associate.IndexOf('MsMonFlowUnlink(flowId)')
if ($unlink -lt 0) { throw 'MsMonAssociateFlow does not unlink by the captured flow id' }
$noAssociation = $associate.IndexOf('0xC0000001')
if ($noAssociation -lt 0 -or $unlink -lt $noAssociation) {
    throw 'the unlink/free is not restricted to the no-association result'
}
$free = $associate.IndexOf('ExFreePoolWithTag(context', $unlink)
if ($free -lt 0 -or $free -lt $unlink) { throw 'ExFreePoolWithTag runs before the unlink decides ownership' }

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
