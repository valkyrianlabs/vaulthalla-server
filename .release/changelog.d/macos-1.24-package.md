- Build: ops/Mfa.hpp includes <nlohmann/json.hpp> (ops::mfa::Status holds a json by value); with only
  json_fwd.hpp it compiled only while an earlier file in its unity chunk included the full header, which 1.24.0's
  macOS -O3 package build no longer did. tools/contracts/test_header_json_complete_contract.py guards every header.
