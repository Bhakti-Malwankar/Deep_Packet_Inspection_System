#include "../include/report_generator.h"
#include <iomanip>
#include <map>
#include <algorithm>

namespace DPI {

void ReportGenerator::addEvent(const std::string& candidate_ip,
                                const std::string& domain,
                                AppType app,
                                const std::string& action,
                                uint32_t ts_sec) {
    BlockedEvent event;
    event.timestamp    = formatTimestamp(ts_sec);
    event.candidate_ip = candidate_ip;
    event.domain       = domain;
    event.app_name     = appTypeToString(app);
    event.action       = action;
    events_.push_back(event);
}

bool ReportGenerator::exportJSON(const std::string& filename,
                                  const std::string& exam_name) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "[Report] ERROR: Cannot create " << filename << "\n";
        return false;
    }

    file << "{\n";
    file << "  \"exam_name\": \"" << escapeJSON(exam_name) << "\",\n";
    file << "  \"total_events\": " << events_.size() << ",\n";
    file << "  \"total_blocked\": " << getTotalBlocked() << ",\n";
    file << "  \"events\": [\n";

    for (size_t i = 0; i < events_.size(); i++) {
        const auto& e = events_[i];
        file << "    {\n";
        file << "      \"timestamp\": \""    << escapeJSON(e.timestamp)    << "\",\n";
        file << "      \"candidate_ip\": \"" << escapeJSON(e.candidate_ip) << "\",\n";
        file << "      \"domain\": \""       << escapeJSON(e.domain)       << "\",\n";
        file << "      \"app\": \""          << escapeJSON(e.app_name)     << "\",\n";
        file << "      \"action\": \""       << escapeJSON(e.action)       << "\"\n";
        file << "    }";
        if (i + 1 < events_.size()) file << ",";
        file << "\n";
    }

    file << "  ],\n";

    // Per-candidate summary
    std::map<std::string, CandidateSummary> candidates;
    for (const auto& e : events_) {
        auto& c = candidates[e.candidate_ip];
        c.ip = e.candidate_ip;
        c.total_attempts++;
        c.domains_accessed.push_back(e.domain);
        if (e.action == "BLOCKED") {
            c.blocked_attempts++;
            c.blocked_domains.push_back(e.domain);
        }
    }

    file << "  \"candidate_summary\": [\n";
    size_t ci = 0;
    for (const auto& [ip, c] : candidates) {
        file << "    {\n";
        file << "      \"ip\": \""               << escapeJSON(c.ip) << "\",\n";
        file << "      \"total_attempts\": "      << c.total_attempts << ",\n";
        file << "      \"blocked_attempts\": "    << c.blocked_attempts << ",\n";
        file << "      \"blocked_domains\": [";
        for (size_t j = 0; j < c.blocked_domains.size(); j++) {
            file << "\"" << escapeJSON(c.blocked_domains[j]) << "\"";
            if (j + 1 < c.blocked_domains.size()) file << ", ";
        }
        file << "]\n";
        file << "    }";
        if (++ci < candidates.size()) file << ",";
        file << "\n";
    }
    file << "  ]\n";
    file << "}\n";

    file.close();
    std::cout << "[Report] JSON report saved to: " << filename << "\n";
    return true;
}

bool ReportGenerator::exportCSV(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "[Report] ERROR: Cannot create " << filename << "\n";
        return false;
    }

    // Header row
    file << "Timestamp,Candidate_IP,Domain,App,Action\n";

    for (const auto& e : events_) {
        file << e.timestamp    << ","
             << e.candidate_ip << ","
             << e.domain       << ","
             << e.app_name     << ","
             << e.action       << "\n";
    }

    file.close();
    std::cout << "[Report] CSV report saved to: " << filename << "\n";
    return true;
}

void ReportGenerator::printSummary() const {
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                  EXAM INTEGRITY AUDIT REPORT                 ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Total Events:   " << std::setw(5) << events_.size()
              << "                                          ║\n";
    std::cout << "║  Total Blocked:  " << std::setw(5) << getTotalBlocked()
              << "                                          ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";

    // Per candidate breakdown
    std::map<std::string, int> blocked_per_ip;
    for (const auto& e : events_) {
        if (e.action == "BLOCKED") {
            blocked_per_ip[e.candidate_ip]++;
        }
    }

    if (!blocked_per_ip.empty()) {
        std::cout << "║  CANDIDATES WITH BLOCKED ATTEMPTS:                            ║\n";
        for (const auto& [ip, count] : blocked_per_ip) {
            std::cout << "║    " << std::left << std::setw(20) << ip
                      << "  Blocked attempts: " << std::setw(4) << count
                      << "              ║\n";
        }
    } else {
        std::cout << "║  No blocked attempts detected.                                ║\n";
    }
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
}

int ReportGenerator::getTotalBlocked() const {
    int count = 0;
    for (const auto& e : events_) {
        if (e.action == "BLOCKED") count++;
    }
    return count;
}

std::string ReportGenerator::formatTimestamp(uint32_t ts_sec) const {
    std::time_t t = ts_sec;
    std::tm* tm = std::localtime(&t);
    std::ostringstream ss;
    if (tm) {
        ss << std::put_time(tm, "%Y-%m-%d %H:%M:%S");
    } else {
        ss << ts_sec;
    }
    return ss.str();
}

std::string ReportGenerator::escapeJSON(const std::string& s) const {
    std::string out;
    for (char c : s) {
        if (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else out += c;
    }
    return out;
}

} // namespace DPI
