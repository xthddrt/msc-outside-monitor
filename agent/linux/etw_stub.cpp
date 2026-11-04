#include "../etw.h"

/*
 * Linux has no ETW.  The collector keeps its deferral and TCP-owner bookkeeping
 * (shared from etw.cpp) but never starts, so the agent records etw_unavailable.
 */

EtwCollector::~EtwCollector()
{
    Stop();
}

bool EtwCollector::Start(std::string& error)
{
    error = "ETW is a Windows facility; WMI, DNS, RPC, TCPIP and CodeIntegrity providers have no Linux source";
    warnings_.push_back(L"etw_unavailable");
    return false;
}

void EtwCollector::Stop()
{
    started_ = false;
}
