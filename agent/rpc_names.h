#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

const std::vector<std::wstring>& RpcOpnumProperties();
std::wstring RpcGuidText(const GUID& guid);
bool RpcOperationName(const std::wstring& interfaceUuid, uint64_t opnum,
                      std::wstring& service, std::wstring& method);
