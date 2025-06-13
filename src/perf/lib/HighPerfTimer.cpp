#include "HighPerfTimer.h"
#ifdef _WIN32
#include <crtdbg.h>
#else
#include <ctime>
#endif // OLS_PLATFORM_WINDOWS


COLSHighPerfTimer COLSHighPerfTimer::s_GlobalTimer(true);

COLSHighPerfTimer::COLSHighPerfTimer(bool start)
{
    m_StartTime.QuadPart = 0;
    BOOL bRet = QueryPerformanceFrequency(&m_freq);
    if (!bRet)
    {
        // likely memory not alligned
        _ASSERT(FALSE);
    }

    if (start)
    {
        Start();
    }
}

void COLSHighPerfTimer::Start(void)
{
    QueryPerformanceCounter(&m_StartTime);
}

LARGE_INTEGER COLSHighPerfTimer::GetStartTime() const
{
    return m_StartTime;
}

double COLSHighPerfTimer::GetSeconds() const
{
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);
    return (endTime.QuadPart - m_StartTime.QuadPart) / static_cast<double>(m_freq.QuadPart);
}

LONGLONG COLSHighPerfTimer::GetTickTime()
{
    LARGE_INTEGER endtime;
    QueryPerformanceCounter(&endtime);
    return endtime.QuadPart;
}

LONGLONG COLSHighPerfTimer::GetTicksElapsed() const
{
    return GetTickTime() - m_StartTime.QuadPart;
}

LONGLONG COLSHighPerfTimer::GetMilliseconds() const
{
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);
    return GetMilliseconds(endTime.QuadPart - m_StartTime.QuadPart);
}

LONGLONG COLSHighPerfTimer::GetGlobalMilliseconds()
{
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);
    return endTime.QuadPart * 1000 / s_GlobalTimer.m_freq.QuadPart;
}

LONGLONG COLSHighPerfTimer::GetGlobalMicroseconds()
{
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);
    return GetGlobalMicroseconds(endTime.QuadPart);
}

LONGLONG COLSHighPerfTimer::GetGlobalMicroseconds(LONGLONG tickCount)
{
    // This will cause overflow only if delta is at least thousand days. This decreases precision by approx 0.1%
    return tickCount * 1000 / (s_GlobalTimer.m_freq.QuadPart / 1000);
}

LONGLONG COLSHighPerfTimer::GetMicroseconds() const
{
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);
    // This will cause overflow only if delta is at least thousand days. This decreases precision by approx 0.1%
    return (endTime.QuadPart - m_StartTime.QuadPart) * 1000 / (m_freq.QuadPart / 1000);
}

LONGLONG COLSHighPerfTimer::GetMilliseconds(LONGLONG tickCount) const
{
    return tickCount * 1000 / m_freq.QuadPart;
}

LONGLONG COLSHighPerfTimer::GetMicroseconds(LONGLONG tickCount) const
{
    return tickCount * 1000 / (m_freq.QuadPart / 1000);
}

LONGLONG COLSHighPerfTimer::GetMicrosecondsSince(LARGE_INTEGER startTime)
{
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    return GetMicrosecondsSince(startTime, freq.QuadPart);
}

LONGLONG COLSHighPerfTimer::GetMicrosecondsSince(LARGE_INTEGER startTime, LONGLONG freq)
{
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);
    // This will cause overflow only if delta is at least thousand days. This decreases precision by approx 0.1%
    return (endTime.QuadPart - startTime.QuadPart) * 1000 / (freq / 1000);
}

#ifdef OLS_PLATFORM_LINUX

// On Windows, the system APIs `QueryPerformanceCounter` and `QueryPerformanceFrequency` are typically based on TSC register.
// On amd64-based Windows 10+ systems, `QueryPerformanceFrequency` typically returns 10,000,000, which means the resolution
// is 100 nanoseconds.
// 
// On Unix/Linux, the C library and POSIX has released several basic time facilities, among which `clock_gettime` is the one
// supports highest resolution. <https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2008/n2661.htm>
// `clock_gettime` is also used as one implementation of C++11 library `std::high_resolution_clock`.

static constexpr int64_t NS_IN_SECOND = 1'000'000'000LL;

// On the first call, the `tv_sec` part of the current timestamp is recorded as the base time for use in the
// `QueryPerformanceCounter` function to avoid integer overflow.
// The `QueryPerformanceCounter` then returns the value calculated as (`tv_sec.tv_nsec` - baseTimeSec) * `freq`.
// For example, if the base time is 1'720'000'000 and `freq` is 10'000'000, and the current timestamp is 1'723'711'351.123456789,
// the function would return (1'723'711'351.123456789 - 1'720'000'000) * 10'000'000 = 37'113'511'234'567.
BOOL QueryPerformanceCounter(_Out_ LARGE_INTEGER* lpPerformanceCount)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == -1)
    {
        return FALSE;
    }

    static int64_t baseTimeSec = static_cast<int64_t>(ts.tv_sec);

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    int64_t qp = (static_cast<int64_t>(ts.tv_sec) - baseTimeSec) * freq.QuadPart;
    qp += static_cast<int64_t>(ts.tv_nsec) * freq.QuadPart / NS_IN_SECOND;
    lpPerformanceCount->QuadPart = qp;
    return TRUE;
}

BOOL QueryPerformanceFrequency(_Out_ LARGE_INTEGER* lpFrequency)
{
    auto getFreq = []() {
        struct timespec ts;
        if (clock_getres(CLOCK_MONOTONIC_RAW, &ts) == 0 &&
            ts.tv_sec == 0 && ts.tv_nsec > 0 && NS_IN_SECOND % static_cast<int64_t>(ts.tv_nsec) == 0)
        {
            return NS_IN_SECOND / static_cast<int64_t>(ts.tv_nsec);
        }
        _ASSERT(false);
        return static_cast<int64_t>(10000000); // typical value of `QueryPerformanceFrequency` on Windows
        };

    static const int64_t freq = getFreq();
    lpFrequency->QuadPart = freq;
    return TRUE;
}

#endif // OLS_PLATFORM_LINUX

INT64 QpcToUs64(INT64 Qpc, INT64 QpcFrequency)
{
    //
    // Multiply by a big number (1000000, to convert seconds to microseconds)
    // and divide by a big number (QpcFrequency, to convert counts to secs).
    //
    // Avoid overflow with separate multiplication/division of the high and low
    // bits.
    //
    // Taken from QuicTimePlatToUs64 (https://github.com/microsoft/msquic).
    //
    UINT64 High = (Qpc >> 32) * 1000000;
    UINT64 Low = (Qpc & MAXUINT32) * 1000000;
    return
        ((High / QpcFrequency) << 32) +
        ((Low + ((High % QpcFrequency) << 32)) / QpcFrequency);
}


void sTokenBucket::init_token_bucket(int init_capacity, int init_refill_rate) {
    capacity = init_capacity;
    tokens = init_capacity;
    refill_rate = init_refill_rate;
    QueryPerformanceFrequency(&(FreqQpc));
    QueryPerformanceCounter(&(lastCounter));
	//bucket->last_refill = time(NULL);
}
void sTokenBucket::refill_tokens() {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    INT64 elapsedns = QpcToUs64(now.QuadPart - lastCounter.QuadPart, FreqQpc.QuadPart);
    int new_tokens = (int)((double)(elapsedns / 1e6) * (double)refill_rate);

    if (new_tokens > 0) {
        tokens = tokens + new_tokens > capacity ? capacity : tokens + new_tokens;
        lastCounter.QuadPart = now.QuadPart;
    }
}

int sTokenBucket::consume_tokens(int applytokens) {

    refill_tokens();

    if (tokens >= applytokens) {
        tokens -= applytokens;
        return 1;
    }
    else {
        return 0;
    }
}
