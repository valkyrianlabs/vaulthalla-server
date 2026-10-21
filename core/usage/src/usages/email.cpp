#include "usages.hpp"

using namespace vh::protocols::shell;

namespace vh::protocols::shell::email {

namespace {

std::shared_ptr<CommandUsage> baseUsage(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

std::shared_ptr<CommandUsage> providerResendSet(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = baseUsage(parent);
    cmd->aliases = {"set"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Set the encrypted Resend API key using a hidden prompt.";
    cmd->optional_flags = {
        Flag::Alias("api_key", "Prompt for the Resend API key", "api-key"),
        Flag::Alias("yes", "Replace an already stored key without asking", "yes")
    };
    cmd->examples = {
        {"vh email provider resend set", "Prompt for and store the Resend API key."},
        {"vh email provider resend set --api-key", "Explicitly prompt for and store the Resend API key."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> providerResend(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = baseUsage(parent);
    cmd->aliases = {"resend"};
    cmd->description = "Manage Resend email provider credentials.";
    const auto setCmd = providerResendSet(cmd->weak_from_this());
    cmd->subcommands = {setCmd};
    cmd->examples = {
        {"vh email provider resend set", "Prompt for and store the Resend API key."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> providerSesSet(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = baseUsage(parent);
    cmd->aliases = {"set"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Set encrypted SES credentials using hidden prompts.";
    cmd->optional_flags = {
        Flag::Alias("access", "Prompt only for the SES access key ID", "access"),
        Flag::Alias("secret", "Prompt only for the SES secret access key", "secret"),
        Flag::Alias("yes", "Replace already stored credentials without asking", "yes")
    };
    cmd->examples = {
        {"vh email provider ses set", "Prompt for and store both SES credential values."},
        {"vh email provider ses set --access", "Prompt for and store only the SES access key ID."},
        {"vh email provider ses set --secret", "Prompt for and store only the SES secret access key."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> providerSes(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = baseUsage(parent);
    cmd->aliases = {"ses"};
    cmd->description = "Manage SES email provider credentials.";
    const auto setCmd = providerSesSet(cmd->weak_from_this());
    cmd->subcommands = {setCmd};
    cmd->examples = {
        {"vh email provider ses set", "Prompt for and store SES credentials."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> providerUse(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = baseUsage(parent);
    cmd->aliases = {"use"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Select the active email provider.";
    cmd->positionals = {
        Positional::Same("provider", "Provider name: none, resend, or ses")
    };
    cmd->examples = {
        {"vh email provider use ses", "Select SES for operator email delivery."},
        {"vh email provider use none", "Disable provider selection without removing stored secrets."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> provider(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = baseUsage(parent);
    cmd->aliases = {"provider"};
    cmd->description = "Manage operator email provider credentials.";
    const auto resendCmd = providerResend(cmd->weak_from_this());
    const auto sesCmd = providerSes(cmd->weak_from_this());
    const auto useCmd = providerUse(cmd->weak_from_this());
    cmd->subcommands = {resendCmd, sesCmd, useCmd};
    return cmd;
}

std::shared_ptr<CommandUsage> set(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = baseUsage(parent);
    cmd->aliases = {"set"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Set core operator email config values.";
    cmd->positionals = {
        Positional::Same("field", "Field: enabled, operator-enabled, from, reply-to, base-url, resend-endpoint, ses-region, or ses-endpoint"),
        Positional::Same("value", "New value; use none to clear nullable fields")
    };
    cmd->examples = {
        {"vh email set enabled true", "Enable the shared email delivery layer."},
        {"vh email set operator-enabled true", "Enable operator email notifications."},
        {"vh email set from 'Vaulthalla <ops@example.com>'", "Set the sender address."},
        {"vh email set base-url https://vault.example.com", "Set the base URL used in email links."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> recipients(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = baseUsage(parent);
    cmd->aliases = {"recipients"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "List or update operator email recipient groups.";
    cmd->positionals = {
        Positional::Same("group", "Recipient group: alerts, weekly, or security"),
        Positional::Same("action", "Action: list, add, or remove"),
        Positional::Same("email", "Email address for add/remove")
    };
    cmd->examples = {
        {"vh email recipients alerts list", "List alert recipients."},
        {"vh email recipients weekly add ops@example.com", "Add a weekly recap recipient."},
        {"vh email recipients security remove ops@example.com", "Remove a security alert recipient."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> weekly(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = baseUsage(parent);
    cmd->aliases = {"weekly"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Manage weekly recap email preferences.";
    cmd->positionals = {
        Positional::Same("action", "Action: show or set"),
        Positional::Same("field", "Field for set: enabled, weekday, hour, or timezone"),
        Positional::Same("value", "New value")
    };
    cmd->examples = {
        {"vh email weekly show", "Show weekly recap settings."},
        {"vh email weekly set enabled true", "Enable weekly recap emails."},
        {"vh email weekly set weekday monday", "Send weekly recaps on Mondays."},
        {"vh email weekly set hour 8", "Send weekly recaps at hour 8."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> security(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = baseUsage(parent);
    cmd->aliases = {"security"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Manage operator security alert preferences.";
    cmd->positionals = {
        Positional::Same("action", "Action: show or set"),
        Positional::Same("field", "Field for set: enabled or admin-role-changes"),
        Positional::Same("value", "New boolean value")
    };
    cmd->examples = {
        {"vh email security show", "Show security alert settings."},
        {"vh email security set admin-role-changes true", "Enable admin role change emails."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> alerting(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = baseUsage(parent);
    cmd->aliases = {"alerting"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Manage watchdog alerting policy for operator emails.";
    cmd->positionals = {
        Positional::Same("action", "Action: show or set"),
        Positional::Same("field", "Field for set: enabled, min-severity, dedupe-window-minutes, repeat-after-hours, send-recovery, or health-poll-seconds"),
        Positional::Same("value", "New value")
    };
    cmd->examples = {
        {"vh email alerting show", "Show watchdog alerting policy."},
        {"vh email alerting set min-severity warning", "Set the minimum alert severity."},
        {"vh email alerting set send-recovery true", "Send recovery emails after watchdog alerts recover."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> doctor(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = baseUsage(parent);
    cmd->aliases = {"doctor"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Inspect operator email configuration without exposing secrets.";
    cmd->examples = {
        {"vh email doctor", "Show configured provider, sender, recipient counts, and secret presence."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> test(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = baseUsage(parent);
    cmd->aliases = {"test"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Render or send a test operator email.";
    cmd->optional_flags = {
        Flag::Alias("dry_run", "Render and validate without sending", "dry-run"),
        Flag::Alias("send", "Send the rendered test email through the configured provider", "send")
    };
    cmd->optional = {
        Optional::ManyToOne("to", "Override the test recipient for rendering", {"to"}, "email")
    };
    cmd->examples = {
        {"vh email test --dry-run", "Render the configured test email without sending."},
        {"vh email test --dry-run --to ops@example.com", "Render a test email for a specific recipient."},
        {"vh email test --send --to ops@example.com", "Send a test email through the configured provider."}
    };
    return cmd;
}

std::shared_ptr<CommandUsage> history(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = baseUsage(parent);
    cmd->aliases = {"history"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Show recent operator email delivery records.";
    cmd->optional = {
        Optional::ManyToOne("limit", "Maximum records to display", {"limit"}, "count")
    };
    cmd->examples = {
        {"vh email history", "Show recent operator email delivery records."},
        {"vh email history --limit 100", "Show up to 100 delivery records."}
    };
    return cmd;
}

}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Email Commands";
    const auto root = baseUsage(parent);
    root->aliases = {"email"};
    root->description = "Manage operator email configuration and diagnostics.";

    const auto providerCmd = provider(root->weak_from_this());
    const auto setCmd = set(root->weak_from_this());
    const auto recipientsCmd = recipients(root->weak_from_this());
    const auto weeklyCmd = weekly(root->weak_from_this());
    const auto securityCmd = security(root->weak_from_this());
    const auto alertingCmd = alerting(root->weak_from_this());
    const auto doctorCmd = doctor(root->weak_from_this());
    const auto testCmd = test(root->weak_from_this());
    const auto historyCmd = history(root->weak_from_this());

    root->subcommands = {
        providerCmd,
        setCmd,
        recipientsCmd,
        weeklyCmd,
        securityCmd,
        alertingCmd,
        doctorCmd,
        testCmd,
        historyCmd
    };
    root->examples = {
        {"vh email provider resend set", "Prompt for and store the Resend API key."},
        {"vh email provider ses set", "Prompt for and store SES credentials."},
        {"vh email provider use ses", "Select SES as the active provider."},
        {"vh email recipients alerts add ops@example.com", "Add an alert recipient."},
        {"vh email weekly set enabled true", "Enable weekly recap emails."},
        {"vh email doctor", "Inspect operator email configuration without leaking secrets."},
        {"vh email test --dry-run", "Render the test operator email without sending."},
        {"vh email test --send --to ops@example.com", "Send the test operator email through the configured provider."},
        {"vh email history --limit 100", "Show recent operator email delivery records."}
    };

    book->root = root;
    return book;
}

}
