#ifndef TIMER_HPP
#define TIMER_HPP

#include <assert.h>
#include <chrono>

class Timer {
private:
    std::chrono::high_resolution_clock::time_point t0;
    double total_time_sec;
    bool status;

public:
    Timer()
    {
        total_time_sec = 0;
        status = false;
    };
    void start();
    void stop();
    void clear();
    double elapse_sec() const
    {
        assert(status == false);
        return total_time_sec;
    }
};

void Timer::start()
{
    assert(status == false);
    t0 = std::chrono::high_resolution_clock::now();
    status = true;
}
void Timer::stop()
{
    assert(status == true);
    auto t1 = std::chrono::high_resolution_clock::now();
    auto time_span_sec = std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0);
    // auto time_span_ms = std::chrono::duration_cast<std::chrono::milliseconds<double>>(t1-t0);
    total_time_sec += time_span_sec.count();
    status = false;
}
void Timer::clear()
{
    total_time_sec = 0;
    status = false;
}

#endif // TIMER_HPP