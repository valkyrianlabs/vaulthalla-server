#include "../helpers/share_fakes.hpp"
#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "ops/Error.hpp"
#include "share/TargetResolver.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <stdexcept>

using namespace vh::share;

namespace {

namespace share_fx = vh::test::shares;

Principal makeFsPrincipal() {
    Principal principal;
    principal.share_id = "00000000-0000-4000-8000-000000000101";
    principal.share_session_id = "00000000-0000-4000-8000-000000000201";
    principal.vault_id = 42;
    principal.root_entry_id = 10;
    principal.root_path = "/shared";
    principal.grant.vault_id = 42;
    principal.grant.root_entry_id = 10;
    principal.grant.root_path = "/shared";
    principal.grant.target_type = TargetType::Directory;
    principal.grant.allowed_ops = bit(Operation::Metadata) | bit(Operation::List);
    principal.expires_at = 1'800'003'600;
    return principal;
}

std::shared_ptr<share_fx::FakeEntryProvider> providerWithSharedTree() {
    auto provider = std::make_shared<share_fx::FakeEntryProvider>();
    provider->add(share_fx::makeDir(10, 42, "/shared"));
    provider->add(share_fx::makeDir(11, 42, "/shared/reports", 10));
    provider->add(share_fx::makeFile(12, 42, "/shared/reports/q1.pdf", 11, "application/pdf"));
    provider->add(share_fx::makeFile(13, 42, "/shared/readme.txt", 10, "application/pdf"));
    provider->add(share_fx::makeDir(20, 42, "/shared_evil"));
    return provider;
}

}

TEST(ShareFsResolutionTest, ResolvesRootPathAndMetadataGrant) {
    const auto provider = providerWithSharedTree();
    const TargetResolver resolver(provider);
    const auto principal = makeFsPrincipal();

    const auto target = resolver.resolve(principal, {
        .path = "/shared",
        .operation = Operation::Metadata
    });

    EXPECT_EQ(target.vault_id, 42u);
    EXPECT_EQ(target.root_entry_id, 10u);
    EXPECT_EQ(target.vault_path, "/shared");
    EXPECT_EQ(target.share_path, "/");
    ASSERT_NE(target.entry, nullptr);
    EXPECT_EQ(target.entry->id, 10u);
}

TEST(ShareFsResolutionTest, ResolvesNormalizedDescendantAndDuplicateSlashes) {
    const auto provider = providerWithSharedTree();
    const TargetResolver resolver(provider);
    const auto principal = makeFsPrincipal();

    const auto target = resolver.resolve(principal, {
        .path = "//shared//reports///q1.pdf",
        .operation = Operation::Metadata
    });

    EXPECT_EQ(target.vault_path, "/shared/reports/q1.pdf");
    EXPECT_EQ(target.share_path, "/reports/q1.pdf");
    EXPECT_EQ(target.target_type, TargetType::File);
}

TEST(ShareFsResolutionTest, DeniesPathEscapeAndPrefixTrick) {
    const auto provider = providerWithSharedTree();
    const TargetResolver resolver(provider);
    const auto principal = makeFsPrincipal();

    EXPECT_THROW({ (void)resolver.resolve(principal, {
        .path = "/shared/../secret.txt",
        .operation = Operation::Metadata
    }); }, std::runtime_error);

    EXPECT_THROW({ (void)resolver.resolve(principal, {
        .path = "../shared/reports/q1.pdf",
        .operation = Operation::Metadata
    }); }, std::runtime_error);

    EXPECT_THROW({ (void)resolver.resolve(principal, {
        .path = "/shared_evil",
        .operation = Operation::Metadata
    }); }, std::runtime_error);
}

TEST(ShareFsResolutionTest, DeniesCrossVaultAndMissingOperation) {
    const auto provider = providerWithSharedTree();
    const TargetResolver resolver(provider);
    auto principal = makeFsPrincipal();

    EXPECT_THROW({ (void)resolver.resolve(principal, {
        .path = "/shared/reports",
        .operation = Operation::Metadata,
        .vault_id = 43
    }); }, std::runtime_error);

    principal.grant.allowed_ops &= ~bit(Operation::List);
    EXPECT_THROW({ (void)resolver.resolve(principal, {
        .path = "/shared/reports",
        .operation = Operation::List,
        .expected_target_type = TargetType::Directory
    }); }, std::runtime_error);
}

TEST(ShareFsResolutionTest, EnforcesListDirectoryTargetAndRejectsFileTargetList) {
    const auto provider = providerWithSharedTree();
    const TargetResolver resolver(provider);
    auto principal = makeFsPrincipal();

    const auto target = resolver.resolve(principal, {
        .path = "/shared/reports",
        .operation = Operation::List,
        .expected_target_type = TargetType::Directory
    });
    EXPECT_EQ(target.target_type, TargetType::Directory);

    EXPECT_THROW({ (void)resolver.resolve(principal, {
        .path = "/shared/reports/q1.pdf",
        .operation = Operation::List,
        .expected_target_type = TargetType::Directory
    }); }, std::runtime_error);

    auto filePrincipal = principal;
    filePrincipal.root_entry_id = 12;
    filePrincipal.root_path = "/shared/reports/q1.pdf";
    filePrincipal.grant.root_entry_id = 12;
    filePrincipal.grant.root_path = "/shared/reports/q1.pdf";
    filePrincipal.grant.target_type = TargetType::File;
    EXPECT_THROW({ (void)resolver.resolve(filePrincipal, {
        .path = "/shared/reports/q1.pdf",
        .operation = Operation::List,
        .expected_target_type = TargetType::Directory
    }); }, std::runtime_error);
}

TEST(ShareFsResolutionTest, FailsClosedWhenRootEntryMovedOrTargetMissing) {
    const auto provider = providerWithSharedTree();
    const TargetResolver resolver(provider);
    auto principal = makeFsPrincipal();

    provider->by_id.at(10)->path = "/renamed";
    EXPECT_THROW({ (void)resolver.resolve(principal, {
        .path = "/shared",
        .operation = Operation::Metadata
    }); }, std::runtime_error);

    provider->by_id.at(10)->path = "/shared";
    EXPECT_THROW({ (void)resolver.resolve(principal, {
        .path = "/shared/missing.txt",
        .operation = Operation::Metadata
    }); }, std::runtime_error);
}

TEST(ShareFsResolutionTest, ListsChildrenOnlyWhenTheyRemainInsideScope) {
    const auto provider = providerWithSharedTree();
    const TargetResolver resolver(provider);
    const auto principal = makeFsPrincipal();

    const auto target = resolver.resolve(principal, {
        .path = "/shared",
        .operation = Operation::List,
        .expected_target_type = TargetType::Directory
    });
    auto children = resolver.listChildren(principal, target);
    ASSERT_EQ(children.size(), 2u);

    provider->children[10].push_back(share_fx::makeFile(99, 42, "/outside.txt", 10, "application/pdf"));
    EXPECT_THROW({ (void)resolver.listChildren(principal, target); }, std::runtime_error);
}

TEST(ShareFsResolutionTest, CanConvertShareRelativePathForInternalCallers) {
    const auto provider = providerWithSharedTree();
    const TargetResolver resolver(provider);
    const auto principal = makeFsPrincipal();

    const auto target = resolver.resolve(principal, {
        .path = "/reports/q1.pdf",
        .operation = Operation::Metadata,
        .path_mode = TargetPathMode::ShareRelative
    });

    EXPECT_EQ(target.vault_path, "/shared/reports/q1.pdf");
    EXPECT_EQ(target.share_path, "/reports/q1.pdf");
}

// sharing.* (#164): every file access through a link re-checks the switches, including a principal that was
// resolved (and cached by the HTTP lane) before the operator turned its kind of link off.
TEST(ShareFsResolutionTest, RefusesEveryAccessWhileItsKindOfLinkIsDisabled) {
    const auto provider = providerWithSharedTree();
    const TargetResolver resolver(provider);
    auto principal = makeFsPrincipal();
    const TargetResolveRequest request{.path = "/shared", .operation = Operation::Metadata};

    const auto previous = vh::config::Registry::get();
    struct Restore {
        const vh::config::Config& cfg;
        ~Restore() { vh::config::Registry::set(cfg); }
    } restore{previous};

    auto cfg = previous;
    cfg.sharing.enable_anonymous = false;
    vh::config::Registry::set(cfg);
    principal.access_mode = AccessMode::Public;
    EXPECT_THROW({ (void)resolver.resolve(principal, request); }, vh::ops::Denied);
    principal.access_mode = AccessMode::EmailValidated;
    EXPECT_NO_THROW({ (void)resolver.resolve(principal, request); });

    cfg.sharing.enable_anonymous = true;
    cfg.sharing.enabled = false;
    vh::config::Registry::set(cfg);
    EXPECT_THROW({ (void)resolver.resolve(principal, request); }, vh::ops::Denied);
    // Folder listings and ZIP plans (#143) go through resolveListedChild: same gate.
    vh::config::Registry::set(previous);
    const auto parent = resolver.resolve(principal, {
        .path = "/shared", .operation = Operation::List, .expected_target_type = TargetType::Directory});
    const auto children = resolver.listChildren(principal, parent);
    ASSERT_FALSE(children.empty());
    vh::config::Registry::set(cfg);
    EXPECT_THROW({ (void)resolver.resolveListedChild(principal, parent, children.front(), Operation::Metadata); },
                 vh::ops::Denied);

    vh::config::Registry::set(previous);
    EXPECT_NO_THROW({ (void)resolver.resolve(principal, request); });
}

// Folder downloads (#143) authorize each listed entry with resolveListedChild instead of resolve(): the decision
// and the resolved target must be the same, only the per-entry root/entry reloads are skipped.
TEST(ShareFsResolutionTest, ResolveListedChildMatchesResolveForEveryListedEntry) {
    const auto provider = providerWithSharedTree();
    const TargetResolver resolver(provider);

    for (const uint32_t extraOps : {0u, bit(Operation::Download), bit(Operation::Download) | bit(Operation::Preview)}) {
        auto principal = makeFsPrincipal();
        principal.grant.allowed_ops |= extraOps;
        for (const auto* dirPath : {"/shared", "/shared/reports"}) {
            const auto parent = resolver.resolve(principal, {
                .path = dirPath,
                .operation = Operation::List,
                .expected_target_type = TargetType::Directory
            });
            for (const auto& child : resolver.listChildren(principal, parent)) {
                for (const auto op : {Operation::Metadata, Operation::List, Operation::Download, Operation::Preview}) {
                    std::optional<ResolvedTarget> viaResolve, viaListed;
                    std::string resolveError, listedError;
                    try {
                        viaResolve = resolver.resolve(principal, {
                            .path = TargetResolver::shareRelativePath(principal, child->path.string()),
                            .operation = op,
                            .path_mode = TargetPathMode::ShareRelative,
                            .expected_target_type = TargetResolver::targetTypeOf(*child)
                        });
                    } catch (const std::exception& e) {
                        resolveError = e.what();
                    }
                    try {
                        viaListed = resolver.resolveListedChild(principal, parent, child, op);
                    } catch (const std::exception& e) {
                        listedError = e.what();
                    }
                    const auto where = child->path.string() + " op " + std::to_string(static_cast<int>(op)) +
                                       " ops " + std::to_string(principal.grant.allowed_ops);
                    ASSERT_EQ(viaResolve.has_value(), viaListed.has_value())
                        << where << ": " << resolveError << " / " << listedError;
                    EXPECT_EQ(resolveError, listedError) << where;
                    if (!viaResolve) continue;
                    EXPECT_EQ(viaResolve->vault_path, viaListed->vault_path) << where;
                    EXPECT_EQ(viaResolve->share_path, viaListed->share_path) << where;
                    EXPECT_EQ(viaResolve->requested_path, viaListed->requested_path) << where;
                    EXPECT_EQ(viaResolve->root_path, viaListed->root_path) << where;
                    EXPECT_EQ(viaResolve->target_type, viaListed->target_type) << where;
                    EXPECT_EQ(viaResolve->operation, viaListed->operation) << where;
                    EXPECT_EQ(viaResolve->entry->id, viaListed->entry->id) << where;
                    EXPECT_EQ(viaResolve->root_entry->id, viaListed->root_entry->id) << where;
                }
            }
        }
    }
}

TEST(ShareFsResolutionTest, ResolveListedChildRefusesEntriesThatAreNotListedChildrenInScope) {
    const auto provider = providerWithSharedTree();
    const TargetResolver resolver(provider);
    auto principal = makeFsPrincipal();
    principal.grant.allowed_ops |= bit(Operation::Download);
    const auto parent = resolver.resolve(principal, {
        .path = "/shared",
        .operation = Operation::List,
        .expected_target_type = TargetType::Directory
    });

    // A grandchild (not a child of the listed directory), outside the share, another vault, a missing entry.
    EXPECT_THROW({ (void)resolver.resolveListedChild(principal, parent, provider->by_id.at(12), Operation::Download); },
                 std::runtime_error);
    EXPECT_THROW({ (void)resolver.resolveListedChild(principal, parent, share_fx::makeFile(98, 42, "/outside.txt", 10),
                                                     Operation::Download); }, std::runtime_error);
    EXPECT_THROW({ (void)resolver.resolveListedChild(principal, parent, share_fx::makeFile(97, 43, "/shared/x.txt", 10),
                                                     Operation::Download); }, std::runtime_error);
    EXPECT_THROW({ (void)resolver.resolveListedChild(principal, parent, nullptr, Operation::Download); },
                 std::runtime_error);
    // A file is not a listing.
    const auto file = resolver.resolve(principal, {.path = "/shared/readme.txt", .operation = Operation::Download});
    EXPECT_THROW({ (void)resolver.resolveListedChild(principal, file, provider->by_id.at(13), Operation::Download); },
                 std::runtime_error);
}
