#include "usages.hpp"
#include "ArgsGenerator.hpp"

using namespace vh::protocols::shell;

namespace vh::protocols::shell::aku {

static std::shared_ptr<CommandUsage> buildBaseUsage(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

std::string usage_provider() {
    const std::vector<std::string> providers = {
        "aws", "cloudflare-r2", "wasabi", "backblaze-b2", "digitalocean",
        "minio", "ceph", "storj", "other"
    };
    std::string options = "provider options: [";
    for (const auto& opt : providers) options += opt + " | ";
    options.pop_back(); // remove last space
    options.pop_back(); // remove last '|'
    options += "]";
    return options;
}

static const auto keyNamePos = Positional::Alias("api_key_name", "Name for the new API key", "name");
static const auto keyNameOpt = Optional::Mirrored("api_key_name", "Name for the new API key", "name");
static const auto accessKey = Option::Single("access_key", "Access key for the S3 provider", "access", "accessKey");
static const auto secretKey = Option::Single("secret_key", "Secret key for the S3 provider", "secret", "secret");
static const auto provider = Option::Mirrored("s3_provider", "S3 provider (" + usage_provider() + ")", "provider");
static const auto endpoint = Option::Multi("endpoint", "Custom endpoint URL for the S3 provider (currently required for all providers)", {"endpoint", "url"}, {"endpoint"});
static const auto region = Optional::Same("region", "Region for the S3 provider", "auto");
static const auto apiKeyPos = Positional::WithAliases("api_key", "ID of the API key to delete", {"id", "api_key_id"});

static std::shared_ptr<CommandUsage> list(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"list", "ls"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "List all API keys in the system.";
    cmd->optional_flags = { jsonFlag };
    cmd->optional = listQueryOptions();
    cmd->examples = {
        {"vh api-keys", "List all API keys in the system."},
        {"vh api-key", "List all API keys in the system (using alias)."},
        {"vh aku", "List all API keys in the system (using shortest alias)."},
        {"vh api-keys --json", "List all API keys in JSON format."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> create(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"create", "new", "add", "mk"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Create a new API key for accessing S3 storage.";
    cmd->positionals = { keyNamePos };
    cmd->required = { accessKey, secretKey, provider, endpoint };
    cmd->optional = { region };
    cmd->examples = {
        {"vh api-key create mykey --access AKIA... --secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY --provider aws --endpoint https://s3.us-east-1.amazonaws.com --region us-east-1",
         "Create a new API key named 'mykey' for AWS S3 in the us-east-1 region."},
        {"vh api-key mk r2key --access <accessKey> --secret <secret> --provider cloudflare-r2 --endpoint https://<account_id>.r2.cloudflarestorage.com",
         "Create a new API key named 'r2key' for Cloudflare R2 (using alias)."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> remove(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"delete", "remove", "del", "rm"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Delete an existing API key by ID.";
    cmd->positionals = { apiKeyPos };
    cmd->examples = {
        {"vh api-key delete 42", "Delete the API key with ID 42."},
        {"vh api-key rm 42", "Delete the API key with ID 42 (using alias)."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> info(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"info", "show", "get"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Display detailed information about an API key.";
    cmd->positionals = { apiKeyPos };
    cmd->examples = {
        {"vh api-key info 42", "Show information for the API key with ID 42."},
        {"vh api-key show 42", "Show information for the API key with ID 42 (using alias)."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> base(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"api-key", "aku", "ak"};
    cmd->pluralAliasImpliesList = true;
    cmd->description = "Manage a single API key.";

    const auto listCmd = list(cmd->weak_from_this());
    const auto createCmd = create(cmd->weak_from_this());
    const auto removeCmd = remove(cmd->weak_from_this());
    const auto infoCmd = info(cmd->weak_from_this());

    const auto createMultiple = TestCommandUsage::Multiple(createCmd);
    const auto createSingle = TestCommandUsage::Single(createCmd);
    const auto removeSingle = TestCommandUsage::Single(removeCmd);
    const auto removeMultiple = TestCommandUsage::Multiple(removeCmd);
    const auto infoSingle = TestCommandUsage::Single(infoCmd);

    listCmd->test_usage.setup = { createMultiple };
    listCmd->test_usage.teardown = { removeMultiple };

    createCmd->test_usage.lifecycle = { infoSingle };
    createCmd->test_usage.teardown = { removeSingle };

    removeCmd->test_usage.setup = { createSingle };

    infoCmd->test_usage.setup = { createMultiple };
    infoCmd->test_usage.teardown = { removeMultiple };

    cmd->subcommands = { listCmd, createCmd, removeCmd, infoCmd };
    return cmd;
}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "API Key Commands";
    book->root = base(parent);
    return book;
}

}
