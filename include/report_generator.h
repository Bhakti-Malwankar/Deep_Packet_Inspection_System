#ifndef DPI_REPORT_GENERATOR_H
#define DPI_REPORT_GENERATOR_H

#include "types.h"
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <ctime>

namespace DPI {

// Represents one blocked access event
struct BlockedEvent {
    std::string timestamp;      // When it happened
    std::string candidate_ip;   // Which candidate (by IP)
    std::string domain;         // What domain they tried to access
    std::string app_name;       // App name e.g. "OpenAI (BLOCKED)"
    std::string action;         // "BLOCKED" or "ALLOWED"
};

// Represents per-candidate summary
struct CandidateSummary {
    std::string ip;
    int total_attempts = 0;
    int blocked_attempts = 0;
    std::vector<std::string> domains_accessed;
    std::vector<std::string> blocked_domains;
};

class ReportGenerator {
public:
    // Add a blocked/allowed event to the report
    void addEvent(const std::string& candidate_ip,
                  const std::string& domain,
                  AppType app,
                  const std::string& action,
                  uint32_t ts_sec);

    // Export full report to JSON file
    bool exportJSON(const std::string& filename,
                    const std::string& exam_name) const;

    // Export summary to CSV file
    bool exportCSV(const std::string& filename) const;

    // Print summary to console
    void printSummary() const;

    int getTotalEvents() const { return events_.size(); }
    int getTotalBlocked() const;

private:
    std::vector<BlockedEvent> events_;

    std::string formatTimestamp(uint32_t ts_sec) const;
    std::string escapeJSON(const std::string& s) const;
};

} // namespace DPI
#endif // DPI_REPORT_GENERATOR_H
