#ifndef DPI_EXAM_MODE_H
#define DPI_EXAM_MODE_H

#include "../include/types.h"
#include <string>
#include <set>
#include <iostream>

namespace DPI {

const std::set<AppType> EXAM_BLOCKED_APPS = {
    AppType::OPENAI,
    AppType::ANTHROPIC,
    AppType::CLUELY,
    AppType::PARAKEET,
    AppType::GEMINI,
    AppType::COPILOT,
    AppType::PERPLEXITY,
    AppType::ANYDESK,
    AppType::TEAMVIEWER,
    AppType::DISCORD,
    AppType::TELEGRAM,
    AppType::WHATSAPP,
};

class ExamModeEngine {
public:
    ExamConfig config;

    void enable(ExamMode mode, const std::string& allowed_domain, 
                const std::string& exam_name) {
        config.mode = mode;
        config.allowed_domain = allowed_domain;
        config.exam_name = exam_name;
        std::cout << "\n[EXAM MODE ACTIVE] " << exam_name << "\n";
        if (mode == ExamMode::WHITELIST) {
            std::cout << "[EXAM MODE] Only allowing: " << allowed_domain << "\n";
            std::cout << "[EXAM MODE] ALL other domains will be BLOCKED\n\n";
        } else if (mode == ExamMode::BLOCKLIST) {
            std::cout << "[EXAM MODE] Blocking: Cluely, Parakeet, OpenAI, "
                         "Anthropic, Gemini, Copilot, AnyDesk, TeamViewer\n\n";
        }
    }

    bool shouldBlock(AppType app, const std::string& sni) const {
        if (config.mode == ExamMode::OFF) return false;
        if (config.mode == ExamMode::BLOCKLIST) {
            return EXAM_BLOCKED_APPS.count(app) > 0;
        }
        if (config.mode == ExamMode::WHITELIST) {
            if (!config.allowed_domain.empty() &&
                sni.find(config.allowed_domain) != std::string::npos) {
                return false;
            }
            return true;
        }
        return false;
    }

    void logBlock(const std::string& sni, AppType app, 
                  const std::string& src_ip) const {
        std::cout << "[EXAM BLOCK] Candidate " << src_ip
                  << " tried to access: " << sni
                  << " (" << appTypeToString(app) << ")\n";
    }
};

} // namespace DPI
#endif // DPI_EXAM_MODE_H
