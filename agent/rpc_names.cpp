#include "rpc_names.h"
#include <algorithm>
#include <cwctype>

const std::vector<std::wstring>& RpcOpnumProperties()
{
    static const std::vector<std::wstring> names = { L"ProcNum", L"OpNum", L"OperationNum" };
    return names;
}

std::wstring RpcGuidText(const GUID& guid)
{
    wchar_t text[40];
    swprintf_s(text, L"%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               guid.Data1, guid.Data2, guid.Data3,
               guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
               guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return text;
}

bool RpcOperationName(const std::wstring& interfaceUuid, uint64_t opnum,
                      std::wstring& service, std::wstring& method)
{
    struct Entry { const wchar_t* uuid; uint64_t opnum; const wchar_t* service; const wchar_t* method; };
    static const Entry entries[] = {
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 0, L"WTS/TermSrvSession", L"RpcOpenSession" },
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 1, L"WTS/TermSrvSession", L"RpcCloseSession" },
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 4, L"WTS/TermSrvSession", L"RpcLogoff" },
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 5, L"WTS/TermSrvSession", L"RpcGetUserName" },
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 6, L"WTS/TermSrvSession", L"RpcGetTerminalName" },
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 7, L"WTS/TermSrvSession", L"RpcGetState" },
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 12, L"WTS/TermSrvSession", L"RpcGetSessionInformation" },
        { L"484809d6-4239-471b-b5bc-61df8c23ac48", 17, L"WTS/TermSrvSession", L"RpcGetSessionInformationEx" },
        { L"88143fd0-c28d-4b2b-8fef-8d882f6a9390", 0, L"WTS/TermSrvEnumeration", L"RpcOpenEnum" },
        { L"88143fd0-c28d-4b2b-8fef-8d882f6a9390", 1, L"WTS/TermSrvEnumeration", L"RpcCloseEnum" },
        { L"88143fd0-c28d-4b2b-8fef-8d882f6a9390", 5, L"WTS/TermSrvEnumeration", L"RpcGetEnumResult" },
        { L"88143fd0-c28d-4b2b-8fef-8d882f6a9390", 8, L"WTS/TermSrvEnumeration", L"RpcGetSessionIds" },
        { L"88143fd0-c28d-4b2b-8fef-8d882f6a9390", 9, L"WTS/TermSrvEnumeration", L"RpcGetEnumResultEx" },
        { L"88143fd0-c28d-4b2b-8fef-8d882f6a9390", 10, L"WTS/TermSrvEnumeration", L"RpcGetAllSessions" },
        { L"88143fd0-c28d-4b2b-8fef-8d882f6a9390", 11, L"WTS/TermSrvEnumeration", L"RpcGetAllSessionsEx" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 0, L"WTS/RCMPublic", L"RpcGetClientData" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 1, L"WTS/RCMPublic", L"RpcGetConfigData" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 2, L"WTS/RCMPublic", L"RpcGetProtocolStatus" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 3, L"WTS/RCMPublic", L"RpcGetLastInputTime" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 4, L"WTS/RCMPublic", L"RpcGetRemoteAddress" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 8, L"WTS/RCMPublic", L"RpcGetAllListeners" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 9, L"WTS/RCMPublic", L"RpcGetSessionProtocolLastInputTime" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 10, L"WTS/RCMPublic", L"RpcGetUserCertificates" },
        { L"bde95fdf-eee0-45de-9e12-e5a61cd0d4fe", 11, L"WTS/RCMPublic", L"RpcQuerySessionData" },
        { L"6bffd098-a112-3610-9833-46c3f87e345a", 0, L"Wkssvc", L"NetrWkstaGetInfo" },
        { L"6bffd098-a112-3610-9833-46c3f87e345a", 2, L"Wkssvc", L"NetrWkstaUserEnum" },
        { L"12345778-1234-abcd-ef00-0123456789ab", 0, L"LSA/lsarpc", L"LsarClose" },
        { L"12345778-1234-abcd-ef00-0123456789ab", 6, L"LSA/lsarpc", L"LsarOpenPolicy" },
        { L"12345778-1234-abcd-ef00-0123456789ab", 7, L"LSA/lsarpc", L"LsarQueryInformationPolicy" },
        { L"12345778-1234-abcd-ef00-0123456789ab", 14, L"LSA/lsarpc", L"LsarLookupNames" },
        { L"12345778-1234-abcd-ef00-0123456789ab", 15, L"LSA/lsarpc", L"LsarLookupSids" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 0, L"SAMR", L"SamrConnect" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 1, L"SAMR", L"SamrCloseHandle" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 5, L"SAMR", L"SamrLookupDomainInSamServer" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 6, L"SAMR", L"SamrEnumerateDomainsInSamServer" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 7, L"SAMR", L"SamrOpenDomain" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 13, L"SAMR", L"SamrEnumerateUsersInDomain" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 17, L"SAMR", L"SamrLookupNamesInDomain" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 18, L"SAMR", L"SamrLookupIdsInDomain" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 57, L"SAMR", L"SamrConnect2" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 61, L"SAMR", L"SamrConnect3" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 62, L"SAMR", L"SamrConnect4" },
        { L"12345778-1234-abcd-ef00-0123456789ac", 64, L"SAMR", L"SamrConnect5" },
    };
    std::wstring normalized = interfaceUuid;
    normalized.erase(std::remove(normalized.begin(), normalized.end(), L'{'), normalized.end());
    normalized.erase(std::remove(normalized.begin(), normalized.end(), L'}'), normalized.end());
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    for (const auto& entry : entries) {
        if (normalized == entry.uuid && opnum == entry.opnum) {
            service = entry.service;
            method = entry.method;
            return true;
        }
    }
    return false;
}
