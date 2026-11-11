// Parsing of the two connection caps: file descriptors and ephemeral ports.
// The inputs are the /proc files a node ships over SSH, so the same parser is
// exercised for the local and the remote path.

#include <iostream>
#include <string>
#include <vector>

#include "slaptop/collector/limits.hpp"

namespace {

int g_failures = 0;

void check(bool condition, const char* expression, const char* file, int line) {
    if (!condition) {
        std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __FILE__, __LINE__)

const char* kLimits =
    "Limit                     Soft Limit           Hard Limit           Units     \n"
    "Max open files            1024                 1048576              files     \n"
    "Max processes             63003                63003                processes \n";

/// Port 40000 (0x9C40) is inside the range below, 389 is not.  The columns
/// after the inode (refcount, sock pointer) are what the kernel actually
/// prints: reading the inode as "the last field" silently counts garbage.
const char* kNetTcp =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  "
    "timeout inode\n"
    "   0: 0100007F:9C40 00000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 "
    "123456 1 0000000000000000 100 0 0 10 0\n"
    "   1: 0100007F:0185 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 "
    "123457 1 0000000000000000 100 0 0 10 0\n"
    "   2: 0100007F:9C41 0100007F:1F90 06 00000000:00000000 03:00000000 00000000     0        0 "
    "0 1 0000000000000000 100 0 0 10 0\n";

void testLocalValues() {
    const slaptop::collector::SocketLimits limits = slaptop::collector::parseSocketLimits(
        kLimits, 42, kNetTcp, "", "1248\t0\t9223372036854775807\n", "32768\t60999\n");
    CHECK(limits.available);
    CHECK(limits.fdsOpen == 42);
    CHECK(limits.fdsLimit == 1024);
    CHECK(limits.fdsFree() == 982);
    CHECK(limits.systemFilesAllocated == 1248);
    CHECK(limits.systemFilesMax == 9223372036854775807ULL);
    CHECK(limits.portFirst == 32768);
    CHECK(limits.portLast == 60999);
    CHECK(limits.portRange() == 60999 - 32768 + 1);
    // Two sockets in range (9C40 established and 9C41 in TIME_WAIT), 0185 out.
    // Without the process' inodes we only know the host total; with them, the
    // count is narrowed to what this instance actually holds.
    CHECK(limits.hostPortsInUse == 2);
    CHECK(limits.portsInUse == 0);
    // Without the process' inodes, only the host figure is known.
    CHECK(limits.hostTimeWait == 1);
    CHECK(limits.timeWait == 0);
    CHECK(limits.portsFree() == limits.portRange() - 2);
}

/// A TIME_WAIT socket of the process itself is counted apart from the host's.
void testOwnTimeWait() {
    // Same row as 9C41 above, but now with the process' inode.
    std::string tcp = kNetTcp;
    const std::size_t at = tcp.find("9C41 0100007F:1F90 06");
    tcp.replace(tcp.find(" 0 1 0000000", at), 4, " 123458 1");
    const slaptop::collector::SocketLimits limits = slaptop::collector::parseSocketLimits(
        kLimits, 2, tcp, "", "", "32768\t60999\n", std::vector<std::uint64_t>{123458});
    CHECK(limits.timeWait == 1);
    CHECK(limits.hostTimeWait == 1);
}

/// The count shown on a card must be the instance's own outbound sockets, not
/// every ephemeral port of the machine.
void testPortsBelongingToTheProcess() {
    const std::vector<std::uint64_t> inodes{123456};
    const slaptop::collector::SocketLimits limits = slaptop::collector::parseSocketLimits(
        kLimits, 3, kNetTcp, "", "", "32768\t60999\n", inodes);
    CHECK(limits.hostPortsInUse == 2);
    CHECK(limits.portsInUse == 1);  // 9C40 only; 9C41 has inode 0
    CHECK(limits.timeWait == 0);    // the TIME_WAIT row belongs to nobody here
    CHECK(limits.portsFree() == limits.portRange() - 2);
}

void testUnlimitedSoftLimit() {
    const slaptop::collector::SocketLimits limits = slaptop::collector::parseSocketLimits(
        "Max open files            unlimited            unlimited            files     \n", 7, "",
        "", "", "");
    CHECK(limits.available);
    CHECK(limits.fdsOpen == 7);
    CHECK(limits.fdsLimit == 0);   // "no limit", not "zero descriptors"
    CHECK(limits.portRange() == 0);
}

void testUnreadableProcess() {
    // Nothing could be read: the caller must show "unavailable", never zeros
    // that would look like an exhausted server.
    const slaptop::collector::SocketLimits limits =
        slaptop::collector::parseSocketLimits("", 0, "", "", "", "");
    CHECK(!limits.available);
}

void testPortsWithoutRange() {
    // A kernel that does not publish ip_local_port_range still gives the fd
    // figures, and no port is counted without a range to compare against.
    const slaptop::collector::SocketLimits limits = slaptop::collector::parseSocketLimits(
        kLimits, 10, kNetTcp, "", "", "");
    CHECK(limits.available);
    CHECK(limits.hostPortsInUse == 0);
    CHECK(limits.hostTimeWait == 1);
}

}  // namespace

int main() {
    testLocalValues();
    testPortsBelongingToTheProcess();
    testOwnTimeWait();
    testUnlimitedSoftLimit();
    testUnreadableProcess();
    testPortsWithoutRange();

    if (g_failures != 0) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "limits: all checks passed\n";
    return 0;
}
