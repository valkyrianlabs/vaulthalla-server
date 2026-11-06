#include "crypto/secrets/Reseal.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "log/Registry.hpp"

#include <algorithm>
#include <stdexcept>

namespace vh::crypto::secrets::reseal {

namespace sealer = platform::sealer;

std::size_t Report::changed() const {
    return static_cast<std::size_t>(std::ranges::count_if(items, [](const Item& i) { return i.changed; }));
}

std::vector<Entry> inventory() {
    std::vector<Entry> out;
    for (const auto& name : KeyProvider::sealedNames()) {
        const KeyProvider provider(name);
        const bool complete = provider.sealedExists();
        out.push_back({.name = name, .policy = complete ? provider.policy() : sealer::Policy::None, .complete = complete});
    }
    return out;
}

Report run(const sealer::Policy target) {
    if (target != sealer::Policy::None && !sealer::policySupported())
        throw std::runtime_error("this platform's sealing has no PCR policy (the Secure Enclave is unaffected by "
                                 "secrets.tpm_pcr_policy)");
    Report report{.target = target};
    for (const auto& name : KeyProvider::sealedNames()) {
        KeyProvider provider(name);
        try {
            const auto r = provider.reseal(target);
            report.items.push_back({.name = name, .from = r.from, .to = r.to, .changed = r.changed});
            if (r.changed)
                log::Registry::crypto()->info("[Reseal] '{}' resealed: {} -> {}", name, sealer::policyName(r.from),
                                              sealer::policyName(r.to));
        } catch (const sealer::PolicyUnsatisfied& e) {
            throw sealer::PolicyUnsatisfied("Resealing stopped at '" + name + "' (" + std::to_string(report.changed()) +
                                            " secret(s) resealed before it; rerun to continue). " + e.what());
        } catch (const std::exception& e) {
            throw std::runtime_error("Resealing stopped at '" + name + "' (" + std::to_string(report.changed()) +
                                     " secret(s) resealed before it; its blob is unchanged, rerun to continue): " +
                                     e.what());
        }
    }
    return report;
}

}
