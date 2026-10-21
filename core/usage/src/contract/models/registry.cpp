// The model registry: every named model, sorted by name (see Contract.hpp WsModel).

#include "models.hpp"

#include <algorithm>
#include <iterator>
#include <stdexcept>

namespace vh::contract::ws {

std::vector<WsModel> models() {
    std::vector<WsModel> all;
    for (auto&& part : {detail::identityModels(), detail::vaultModels(), detail::fsModels(), detail::shareModels(),
                        detail::syncModels(), detail::statsModels(), detail::s3GatewayModels(), detail::adminModels(),
                        detail::recoveryModels(), detail::upstreamModels(), detail::deviceModels(),
                        detail::vaultKeyModels()})
        all.insert(all.end(), std::make_move_iterator(part.begin()), std::make_move_iterator(part.end()));

    std::ranges::sort(all, {}, &WsModel::name);
    if (const auto dup = std::ranges::adjacent_find(all, {}, &WsModel::name); dup != all.end())
        throw std::logic_error("ws model registry declares " + dup->name + " twice");
    return all;
}

std::vector<WsField> modelFields(const std::string& name) {
    for (auto& m : models())
        if (m.name == name) return std::move(m.fields);
    throw std::out_of_range("no ws model named " + name);
}

}
