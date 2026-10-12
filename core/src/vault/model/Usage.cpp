#include "vault/model/Usage.hpp"
#include "db/encoding/timestamp.hpp"

#include <pqxx/row>

using namespace vh::vault::model;
using namespace vh::db::encoding;

Usage::Usage(pqxx::row_ref row)
    : user_id(row["user_id"].as<unsigned int>()),
      storage_volume_id(row["storage_volume_id"].as<unsigned int>()),
      total_bytes(row["total_bytes"].as<unsigned long long>()),
      used_bytes(row["used_bytes"].as<unsigned long long>()),
      created_at(parsePostgresTimestamp(row["created_at"].as<std::string>())),
      updated_at(parsePostgresTimestamp(row["updated_at"].as<std::string>())) {}
