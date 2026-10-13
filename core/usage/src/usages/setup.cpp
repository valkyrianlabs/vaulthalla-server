#include "usages.hpp"

using namespace vh::protocols::shell;

namespace vh::protocols::shell::setup {

static std::shared_ptr<CommandUsage> buildBaseUsage(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

static const auto dbHostReq = Option::Single("host", "Remote PostgreSQL host", "host", "hostname");
static const auto dbPortOpt = Optional::ManyToOne("port", "Remote PostgreSQL port", {"port", "p"}, "port", "5432");
static const auto dbUserReq = Option::Multi("user", "Remote PostgreSQL user", {"user", "u"}, {"username"});
static const auto dbNameReq = Option::Multi("database", "Remote PostgreSQL database name", {"database", "db", "name"}, {"database"});
static const auto dbPassFileReq = Option::Multi("password_file", "Path to file containing remote DB password", {"password-file", "password-path", "pw-file"}, {"path"});
static const auto dbPoolSizeOpt = Optional::ManyToOne("pool_size", "Database pool size", {"pool-size"}, "size");
static const auto interactiveFlag = Flag::WithAliases("interactive_mode", "Prompt for missing remote DB values", {"interactive", "i"});
static const auto nginxDomainOpt = Optional::ManyToOne("domain", "Domain to configure for Vaulthalla nginx integration", {"domain", "d"}, "domain");
static const auto nginxS3DomainOpt = Optional::ManyToOne("s3_domain", "Dedicated HTTPS hostname for the S3 gateway (must differ from --domain). Requires --certbot-dns-cloudflare <credentials>; --certbot cannot be combined with it", {"s3-domain"}, "domain");
static const auto nginxCertbotDnsCloudflareOpt = Optional::ManyToOne("certbot_dns_cloudflare", "Issue/renew one certificate covering --domain and --s3-domain through Cloudflare DNS-01 (python3-certbot-dns-cloudflare); no inbound port 80 is needed. <credentials> is a root-owned, mode 0600 file containing the line 'dns_cloudflare_api_token = <token>', where the token has Zone > DNS > Edit on the zones of both hostnames. Certbot renewals keep reading the file, so leave it in place. Conventional path: /etc/vaulthalla/certbot/cloudflare.ini", {"certbot-dns-cloudflare"}, "credentials");
static const auto nginxCertbotFlag = Flag::WithAliases("certbot_mode", "Issue/renew a Let's Encrypt certificate for --domain with the certbot nginx plugin (HTTP-01: the domain must reach this host on port 80). Not supported with --s3-domain", {"certbot"});

// `vh setup caddy` (macOS): deploy/launchd/vaulthalla-caddy does the work; these are its options, for help and the manpage.
static const auto caddyDomainOpt = Optional::ManyToOne("domain", "The console's hostname. Names under .home.arpa, .internal, .lan, .local, .localhost or .test get a certificate from Vaulthalla's own CA; other names get Let's Encrypt. Required the first time; later runs reuse it", {"domain", "d"}, "domain");
static const auto caddyS3DomainOpt = Optional::ManyToOne("s3_domain", "A second hostname for the S3 gateway (path-style requests), served with the same kind of certificate", {"s3-domain"}, "domain");
static const auto caddyCaScopeOpt = Optional::ManyToOne("ca_scope", "Internal CA only: let it sign for this domain and everything under it (e.g. home.arpa) instead of only the configured hostnames, so a new hostname later needs no new CA on clients", {"ca-scope"}, "domain");
static const auto caddyEmailOpt = Optional::ManyToOne("email", "Contact address for the Let's Encrypt account (expiry notices)", {"email"}, "address");
static const auto caddyCloudflareOpt = Optional::ManyToOne("dns_cloudflare", "Get the public certificate through Cloudflare DNS (DNS-01; no inbound port 80/443 needed). <credentials> is a root-owned 0600 file with the line 'dns_cloudflare_api_token = <token>' (the same file `vh setup nginx` uses); the token needs Zone > DNS > Edit", {"dns-cloudflare"}, "credentials");
static const auto caddyCertOpt = Optional::ManyToOne("cert", "Use your own certificate chain (PEM; with --key). Copied in; rerun to replace it before it expires", {"cert"}, "file");
static const auto caddyKeyOpt = Optional::ManyToOne("key", "The private key of --cert (PEM, unencrypted); stored readable by the service only", {"key"}, "file");
static const auto caddyListenOpt = Optional::ManyToOne("listen", "Listen on this address only instead of every interface", {"listen"}, "address");
static const auto caddyInternalFlag = Flag::WithAliases("internal", "Use Vaulthalla's own CA whatever the hostname's suffix", {"internal"});
static const auto caddyStagingFlag = Flag::WithAliases("acme_staging", "Use Let's Encrypt's staging service (untrusted certificates, generous limits) to rehearse", {"acme-staging"});
static const auto caddyTrustFlag = Flag::WithAliases("trust", "Also trust Vaulthalla's CA on this Mac (System keychain; macOS asks you to confirm)", {"trust"});
static const auto caddyHostsFlag = Flag::WithAliases("hosts_entry", "Also point the hostname(s) at this Mac in its /etc/hosts (a marked line, removed by teardown)", {"hosts-entry"});
static const auto caddyDryRunFlag = Flag::WithAliases("dry_run", "Print the Caddyfile that would be used and change nothing", {"dry-run"});
static const auto caddyStatusFlag = Flag::WithAliases("status", "Show the configured hostnames, the certificate being served and the daemon's state", {"status"});

static std::shared_ptr<CommandUsage> caddy(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"caddy", "https"};
    cmd->description = "macOS: serve Vaulthalla over HTTPS through Caddy (the console, WebSockets, uploads and downloads, "
                       "and optionally the S3 gateway), with certificates handled automatically: Vaulthalla's own CA for "
                       "internal names, Let's Encrypt for public ones, Cloudflare DNS when the host isn't reachable from the "
                       "internet, or your own files. Validates, starts and checks the result; Caddy renews certificates by "
                       "itself. Requires sudo. On Linux, use `vh setup nginx`.";
    cmd->optional = {caddyDomainOpt, caddyS3DomainOpt, caddyCaScopeOpt, caddyEmailOpt, caddyCloudflareOpt, caddyCertOpt,
                     caddyKeyOpt, caddyListenOpt};
    cmd->optional_flags = {caddyInternalFlag, caddyStagingFlag, caddyTrustFlag, caddyHostsFlag, caddyDryRunFlag,
                           caddyStatusFlag};
    cmd->examples = {
        {"sudo vh setup caddy --domain vault.home.arpa --trust", "Internal HTTPS with Vaulthalla's CA, trusted on this Mac."},
        {"sudo vh setup caddy --domain vault.example.com --email you@example.com", "Public HTTPS with Let's Encrypt."},
        {"sudo vh setup caddy --domain vault.example.com --dns-cloudflare /etc/vaulthalla/cloudflare.ini",
         "Public HTTPS through Cloudflare DNS validation."},
        {"sudo vh setup caddy --status", "Show what is configured and the certificate being served."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> db(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"db", "database", "postgres"};
    cmd->description = "Bootstrap Vaulthalla local PostgreSQL integration (role/database) and hand off schema/migrations to normal runtime startup. Requires sudo.";
    cmd->examples = {
        {"sudo vh setup db", "Create/reuse local PostgreSQL role/database, seed runtime DB password handoff when needed, and restart/start runtime service."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> remote_db(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"remote-db", "remote_db", "remote", "rdb"};
    cmd->description = "Configure Vaulthalla to use a remote PostgreSQL database. Requires sudo.";
    cmd->required = {dbHostReq, dbUserReq, dbNameReq, dbPassFileReq};
    cmd->optional = {dbPortOpt, dbPoolSizeOpt};
    cmd->optional_flags = {interactiveFlag};
    cmd->examples = {
        {"sudo vh setup remote-db --host db.example.net --port 5432 --user vaulthalla --database vaulthalla --password-file /root/.secrets/vh-db-pass",
         "Configure remote DB settings, seed runtime DB password handoff, and restart/start service."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> nginx(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"nginx", "proxy"};
    cmd->description = "Generate/deploy Vaulthalla-managed nginx config from canonical runtime config, then validate and reload conservatively. Requires sudo. "
                       "TLS: --certbot issues a certificate for --domain over HTTP-01. --s3-domain needs --certbot-dns-cloudflare <credentials> instead, "
                       "which issues one certificate for both hostnames over Cloudflare DNS-01. Create the credentials file once with "
                       "'sudo install -d -m 0700 /etc/vaulthalla/certbot && sudo install -m 0600 /dev/null /etc/vaulthalla/certbot/cloudflare.ini "
                       "&& sudoedit /etc/vaulthalla/certbot/cloudflare.ini' and add the line 'dns_cloudflare_api_token = <token>' "
                       "(Cloudflare dashboard: My Profile > API Tokens > 'Edit zone DNS' template). Guide: https://vaulthalla.io/docs/s3-gateway/setup";
    cmd->optional = {nginxDomainOpt, nginxS3DomainOpt, nginxCertbotDnsCloudflareOpt};
    cmd->optional_flags = {nginxCertbotFlag};
    cmd->examples = {
        {"sudo vh setup nginx", "Regenerate and apply canonical Vaulthalla-managed nginx config, then validate/reload when safe."},
        {"sudo vh setup nginx --certbot --domain vault.example.com", "Configure Vaulthalla nginx integration and run deterministic certbot issue/renew flow for the domain."},
        {"sudo vh setup nginx --domain vaulthalla.dev --s3-domain s3.vaulthalla.dev --certbot-dns-cloudflare /etc/vaulthalla/certbot/cloudflare.ini",
         "Configure HTTPS web and dedicated S3 hosts using Cloudflare DNS-01 certificates."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> assign_admin(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"assign-admin", "assign_admin", "claim-admin"};
    cmd->description = "Explicitly claim or verify initial CLI super-admin ownership for the current operator.";
    cmd->examples = {
        {"vh setup assign-admin", "Run the explicit admin-claim onboarding step and report whether ownership was newly bound or already configured."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> set_super_admin_password(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"set-super-admin-password", "super-admin-password"};
    cmd->description = "Change the web console password of the built-in super-admin account ('admin'). Asks for the new "
                       "password. Only the Linux user bound as the Vaulthalla super admin (see 'vh setup assign-admin') may "
                       "run it; do not use sudo. Ends the account's web sessions and removes the initial password file "
                       "(/var/lib/vaulthalla/super_admin_initial_password) if it is still there. Keeping the generated "
                       "initial password instead is fine: delete that file.";
    cmd->examples = {
        {"vh setup set-super-admin-password", "Prompt for and set a new web console password for 'admin'."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> base(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"setup"};
    cmd->description = "Perform explicit Vaulthalla integration setup tasks.";
    cmd->examples = {
        {"vh setup assign-admin", "Run explicit admin-claim onboarding for the current operator."},
        {"vh setup set-super-admin-password", "Change the web console password of the built-in 'admin' account."},
        {"sudo vh setup db", "Bootstrap local PostgreSQL integration."},
        {"sudo vh setup remote-db --host db.example.net --user vaulthalla --database vaulthalla --password-file /path/to/password-file", "Configure remote PostgreSQL integration."},
        {"sudo vh setup nginx", "Configure Vaulthalla nginx integration."},
        {"sudo vh setup nginx --certbot --domain vault.example.com", "Configure Vaulthalla nginx integration with explicit certbot handling for the requested domain."},
        {"sudo vh setup nginx --domain vaulthalla.dev --s3-domain s3.vaulthalla.dev --certbot-dns-cloudflare /etc/vaulthalla/certbot/cloudflare.ini",
         "Configure HTTPS web and dedicated S3 hosts using Cloudflare DNS-01 certificates."}
    };
    cmd->subcommands = {
        assign_admin(cmd->weak_from_this()),
        db(cmd->weak_from_this()),
        remote_db(cmd->weak_from_this()),
        nginx(cmd->weak_from_this()),
        caddy(cmd->weak_from_this()),
        set_super_admin_password(cmd->weak_from_this())
    };
    return cmd;
}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Setup Commands";
    book->root = base(parent);
    return book;
}

}
