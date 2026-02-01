#include <iostream>
#include <vector>
#include <chrono>
#include <thread>
#include <cmath>
#include <cstdint>

volatile double sink; // prevent optimizer from removing math

void cpu_and_mem_stress(std::size_t mem_mb, int duration_sec)
{
    const std::size_t bytes = mem_mb * 1024ULL * 1024ULL;
    const std::size_t elements = bytes / sizeof(uint64_t);

    std::vector<uint64_t> buffer(elements);

    auto start = std::chrono::high_resolution_clock::now();

    while (true)
    {
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed =
            std::chrono::duration_cast<std::chrono::seconds>(now - start).count();

        if (elapsed >= duration_sec)
            break;

        // Memory pressure (write + read)
        for (std::size_t i = 0; i < elements; ++i)
        {
            buffer[i] = static_cast<uint64_t>(i ^ 0xDEADBEEF);
        }

        // CPU pressure (floating-point chaos)
        double x = 0.0001;
        for (int i = 0; i < 5'000'000; ++i)
        {
            x += std::sin(x) * std::cos(x);
        }

        sink = x; // stop optimization
    }
}

int main()
{
    constexpr std::size_t MEM_MB = 512; // adjust memory load here
    constexpr int STRESS_SEC = 10;

    std::cout << "CPU + Memory stress test started\n";
    std::cout << "Each cycle: " << STRESS_SEC
        << "s, Memory: " << MEM_MB << " MB\n\n";

    while (true)
    {
        std::cout << "[*] Stress ON\n";
        cpu_and_mem_stress(MEM_MB, STRESS_SEC);

        std::cout << "[*] Stress OFF\n\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}
