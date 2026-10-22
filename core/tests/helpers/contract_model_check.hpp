#pragma once

// Checks what a serializer produces against the model the ws contract declares for it (core/usage: WsModel,
// WsField). Each area's model suite (core/tests/unit/contract/models_*.cpp) serializes seeded instances and hands
// the JSON to a Checker; the contract suite then requires
//   - no problems: every key sent is declared (checkInput: an input model accepts undeclared members), every
//     required field is present, every value has a declared JSON type (and enum value, bounds, element type),
//     recursively through nested models, inline objects, maps, arrays and unions;
//   - no unseen fields: every declared field of every checked model was produced, non-null, by some instance
//     (allowUnseen names the exceptions with the reason), so a model can't declare members nobody sends;
//   - every model in the registry was checked by some suite.

#include "Contract.hpp"

#include <nlohmann/json.hpp>

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace vh::test::contract_models {

using json = nlohmann::json;
using contract::WsField;

class Checker {
  public:
    Checker() {
        for (auto& m : contract::ws::models()) models_.emplace(m.name, std::move(m));
    }

    // `value` must be the JSON of model `name`; `where` names the instance in problem messages.
    void check(const json& value, const std::string& name, const std::string& where) {
        direct_.insert(name);
        std::vector<std::string> out;
        checkModel(value, name, where, out, seen_);
        for (auto& p : out) problems_.push_back(std::move(p));
    }

    // `value` is a document a client sends as model `name` (an input model, e.g. VaultKeyImportDocument): checked the
    // same way, except that members the model doesn't declare, at any depth, are accepted (the reader ignores them).
    void checkInput(const json& value, const std::string& name, const std::string& where) {
        acceptUndeclared_ = true;
        check(value, name, where);
        acceptUndeclared_ = false;
    }

    // A declared field path ("Model.field", "Model.field.sub", "Model.list[].sub", "Model.map.*") no seeded instance
    // can produce, with the reason. Stale entries (the path was seen after all) are problems too.
    void allowUnseen(const std::string& path, std::string reason) { allowed_[path] = std::move(reason); }

    [[nodiscard]] const std::vector<std::string>& problems() const { return problems_; }
    [[nodiscard]] const std::set<std::string>& checkedModels() const { return checked_; }
    [[nodiscard]] const std::set<std::string>& opaqueObjects() const { return opaque_; }

    // Declared paths that no instance produced non-null, minus the allowed ones: of every checked model, or (directOnly)
    // only of the models handed to check() itself. An area suite checks its own models directly and reaches other
    // areas' models through references, so it judges coverage of its own; the combined run judges all of them.
    [[nodiscard]] std::vector<std::string> unseen(const bool directOnly = false) const {
        std::vector<std::string> out;
        for (const auto& path : declared_) {
            if (directOnly && !direct_.contains(path.substr(0, path.find('.')))) continue;
            if (!seen_.contains(path) && !allowed_.contains(path)) out.push_back(path);
        }
        return out;
    }

    // allowUnseen entries that were seen after all, or that name no declared path.
    [[nodiscard]] std::vector<std::string> staleAllowances() const {
        std::vector<std::string> out;
        for (const auto& [path, reason] : allowed_)
            if (seen_.contains(path) || !declared_.contains(path)) out.push_back(path + " (" + reason + ")");
        return out;
    }

    [[nodiscard]] const std::set<std::string>& directlyCheckedModels() const { return direct_; }

  private:
    using Seen = std::set<std::string>;

    static std::string jsonType(const json& v) {
        if (v.is_null()) return "null";
        if (v.is_boolean()) return "boolean";
        if (v.is_number_integer()) return "integer";
        if (v.is_number()) return "number";
        if (v.is_string()) return "string";
        if (v.is_array()) return "array";
        return "object";
    }

    static bool typeMatches(const json& v, const std::string& t) {
        if (t == "null") return v.is_null();
        if (t == "boolean") return v.is_boolean();
        if (t == "integer") return v.is_number_integer();
        if (t == "number") return v.is_number();
        if (t == "string") return v.is_string();
        if (t == "array") return v.is_array();
        if (t == "object") return v.is_object();
        return false;
    }

    static std::string joined(const std::vector<std::string>& v) {
        std::string out;
        for (const auto& s : v) out += (out.empty() ? "" : "|") + s;
        return out;
    }

    // Records the declared paths of a model's fields (nested inline shapes included; referenced models are declared
    // when they are checked themselves).
    void declare(const std::vector<WsField>& fields, const std::string& path) {
        for (const auto& f : fields) declareField(f, path + "." + f.name);
    }

    void declareField(const WsField& f, const std::string& path) {
        declared_.insert(path);
        declareShape(f, path);
    }

    // The paths inside one value's shape: inline members, map values, array elements, union alternatives.
    void declareShape(const WsField& f, const std::string& path) {
        if (!f.fields.empty()) declare(f.fields, f.items == "object" ? path + "[]" : path);
        for (const auto& v : f.values) declareField(v, path + ".*");
        for (const auto& e : f.element) declareField(e, path + "[]");
        for (const auto& a : f.one_of) declareShape(a, path);
    }

    void checkModel(const json& v, const std::string& name, const std::string& where, std::vector<std::string>& out,
                    Seen& seen) {
        const auto it = models_.find(name);
        if (it == models_.end()) {
            out.push_back(where + ": " + name + " is not a declared model");
            return;
        }
        if (checked_.insert(name).second) declare(it->second.fields, name);
        checkObject(v, it->second.fields, name, where, out, seen);
    }

    void checkObject(const json& v, const std::vector<WsField>& fields, const std::string& path,
                     const std::string& where, std::vector<std::string>& out, Seen& seen) {
        if (!v.is_object()) {
            out.push_back(where + ": " + path + " is " + jsonType(v) + ", declared an object");
            return;
        }
        for (const auto& [key, member] : v.items()) {
            if (acceptUndeclared_) break;
            bool declared = false;
            for (const auto& f : fields) declared = declared || f.name == key;
            if (!declared) out.push_back(where + ": " + path + "." + key + " is sent but not declared");
        }
        for (const auto& f : fields) {
            const auto member = v.find(f.name);
            if (member == v.end()) {
                if (f.required) out.push_back(where + ": " + path + "." + f.name + " is declared required but missing");
                continue;
            }
            checkValue(*member, f, path + "." + f.name, where, out, seen);
        }
    }

    void checkValue(const json& v, const WsField& f, const std::string& path, const std::string& where,
                    std::vector<std::string>& out, Seen& seen) {
        bool typed = false;
        for (const auto& t : f.types) typed = typed || typeMatches(v, t);
        if (!typed) {
            out.push_back(where + ": " + path + " is " + jsonType(v) + ", declared " + joined(f.types));
            return;
        }
        if (v.is_null()) return;
        seen.insert(path);

        if (!f.one_of.empty()) {
            std::string tried;
            for (const auto& alt : f.one_of) {
                std::vector<std::string> altProblems;
                Seen altSeen;
                checkValue(v, alt, path, where, altProblems, altSeen);
                if (altProblems.empty()) {
                    seen.insert(altSeen.begin(), altSeen.end());
                    return;
                }
                tried += "\n    - " + altProblems.front();
            }
            out.push_back(where + ": " + path + " matches none of its one_of alternatives:" + tried);
            return;
        }

        if (v.is_string() && !f.enum_values.empty()) {
            bool known = false;
            for (const auto& e : f.enum_values) known = known || e == v.get<std::string>();
            if (!known) out.push_back(where + ": " + path + " = \"" + v.get<std::string>() + "\" is not in its enum");
        }
        if (v.is_number_integer()) {
            if (f.minimum && v.get<long double>() < static_cast<long double>(*f.minimum))
                out.push_back(where + ": " + path + " is below its declared minimum");
            if (f.maximum && v.get<long double>() > static_cast<long double>(*f.maximum))
                out.push_back(where + ": " + path + " is above its declared maximum");
        }
        if (v.is_object()) {
            if (!f.model.empty()) checkModel(v, f.model, where, out, seen);
            else if (!f.fields.empty()) checkObject(v, f.fields, path, where, out, seen);
            else if (!f.values.empty())
                for (const auto& [key, member] : v.items()) checkValue(member, f.values.front(), path + ".*", where, out, seen);
            else opaque_.insert(path);
        }
        if (v.is_array()) {
            for (const auto& e : v) {
                if (!f.element.empty()) {
                    checkValue(e, f.element.front(), path + "[]", where, out, seen);
                    continue;
                }
                if (f.items.empty()) {
                    out.push_back(where + ": " + path + " is an array without a declared element type");
                    break;
                }
                if (!typeMatches(e, f.items) && !(f.items == "number" && e.is_number())) {
                    out.push_back(where + ": " + path + "[] is " + jsonType(e) + ", declared " + f.items);
                    continue;
                }
                if (e.is_string() && !f.item_enum.empty()) {
                    bool known = false;
                    for (const auto& x : f.item_enum) known = known || x == e.get<std::string>();
                    if (!known) out.push_back(where + ": " + path + "[] = \"" + e.get<std::string>() + "\" is not in its enum");
                }
                if (e.is_object()) {
                    if (!f.model.empty()) checkModel(e, f.model, where, out, seen);
                    else if (!f.fields.empty()) checkObject(e, f.fields, path + "[]", where, out, seen);
                    else opaque_.insert(path + "[]");
                }
            }
        }
    }

    std::map<std::string, contract::WsModel> models_;
    std::set<std::string> checked_, direct_, declared_, opaque_;
    Seen seen_;
    std::map<std::string, std::string> allowed_;
    std::vector<std::string> problems_;
    bool acceptUndeclared_ = false;
};

}
