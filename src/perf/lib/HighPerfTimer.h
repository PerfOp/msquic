#pragma once

/*
#include "OLSWinDef.h"
#include "OLSIGlobals.h"
#include "OLSSalStub.h"
*/


#ifdef OLS_PLATFORM_LINUX
BOOL QueryPerformanceCounter(_Out_ LARGE_INTEGER* lpPerformanceCount);
BOOL QueryPerformanceFrequency(_Out_ LARGE_INTEGER* lpFrequency);
#endif

#ifdef _WIN32
#include <windows.h>
#endif

class COLSHighPerfTimer
{
public:
    COLSHighPerfTimer(bool start = false);
    void Start(void);
    double GetSeconds() const;
    static LONGLONG GetTickTime();
    LONGLONG GetTicksElapsed() const;
    LONGLONG GetMilliseconds() const;
    static LONGLONG GetGlobalMilliseconds();
    static LONGLONG GetGlobalMicroseconds();
    static LONGLONG GetGlobalMicroseconds(LONGLONG tickCount);
    LONGLONG GetMicroseconds() const;
    LONGLONG GetMilliseconds(LONGLONG tickCount) const;
    LONGLONG GetMicroseconds(LONGLONG tickCount) const;
    LARGE_INTEGER GetStartTime() const;
    long long GetFrequency() { return m_freq.QuadPart; }

    static LONGLONG GetMicrosecondsSince(LARGE_INTEGER startTime);
    static LONGLONG GetMicrosecondsSince(LARGE_INTEGER startTime, LONGLONG freq);

    // used for time measurements when you have less than 8 bytes to store the start time (e.g. commit latency in
    // replication) saving event start time as difference from global start time requires less bytes
    static COLSHighPerfTimer s_GlobalTimer;

private:
    alignas(8) LARGE_INTEGER m_StartTime;
    alignas(8) LARGE_INTEGER m_freq;
};

typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef INT32 int32_t;
class TokenBucket
{
private:
    uint32_t m_tokens_per_unit;
    int32_t m_max_tokens;
    uint32_t m_usec_per_unit;
    COLSHighPerfTimer m_timer;
    uint64_t m_state = 0;

public:
    TokenBucket(uint32_t qps, uint32_t max_tokens = 0)
        : m_timer(true)
    {
        if (max_tokens != 0)
            m_max_tokens = max_tokens;
        else if (qps * 10L/*sec*/ > uint32_t(-1))
            m_max_tokens = uint32_t(-1);
        else
            m_max_tokens = qps * 10/*sec*/;
        uint32_t usec_per_unit = 1000000, tokens_per_unit = qps;
        while (qps > 0 && usec_per_unit > 0 && (tokens_per_unit % 5 == 0) && (usec_per_unit % 5 == 0))
            usec_per_unit /= 5, tokens_per_unit /= 5;
        while (qps > 0 && usec_per_unit > 0 && (tokens_per_unit % 2 == 0) && (usec_per_unit % 2 == 0))
            usec_per_unit /= 2, tokens_per_unit /= 2;
        m_tokens_per_unit = tokens_per_unit;
        m_usec_per_unit = usec_per_unit;
    }

    bool Use()
    {
        if (m_tokens_per_unit == 0)
            return true;
        uint64_t old_state = m_state;
        while (true)
        {
            int32_t old_token = (int32_t)old_state;
            if (old_token > 0)
            {
                //OLSInterlockedDecrement(&m_state);
                return true;
            }

            uint32_t old_usec = (uint32_t)(old_state >> 32);
            uint32_t new_usec = (uint32_t)m_timer.GetMicroseconds();
            uint32_t delta_unit = (new_usec - old_usec) / m_usec_per_unit;
            if (delta_unit < 1)
                return false;
            new_usec = old_usec + delta_unit * m_usec_per_unit;
            int32_t new_token = old_token + delta_unit * m_tokens_per_unit;
            if (new_token > m_max_tokens)
                new_token = m_max_tokens;
            if (new_token < 0)
                return false;
            /*
            uint64_t new_state = (((uint64_t)new_usec) << 32) | new_token;
            old_state = OLSInterlockedCompareExchange(&m_state, new_state, old_state);
            */
        }
    }
};
INT64 QpcToUs64(INT64 Qpc, INT64 QpcFrequency);

class sTokenBucket {
    int capacity;
    int tokens;
    int refill_rate;
    //time_t last_refill;
    LARGE_INTEGER FreqQpc;
    LARGE_INTEGER lastCounter;
public:
	void init_token_bucket( int init_capacity, int init_refill_rate);
	void refill_tokens();
	int consume_tokens(int applytokens);
};
