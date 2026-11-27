#pragma once

#define FUSE_USE_VERSION 35

#include "resolver/Resolved.hpp"
#include "resolver/Request.hpp"

namespace vh::fuse {
    struct Resolver {
        static resolver::Resolved resolve(const resolver::Request& req);

    private:
        static bool resolveIdentity(const resolver::Request& req, resolver::Resolved& out);
        static bool resolveParentEntry(const resolver::Request& req, resolver::Resolved& out);
        static bool resolveEntry(const resolver::Request& req, resolver::Resolved& out);
        static bool resolveEngine(const resolver::Request& req, resolver::Resolved& out);
        static bool resolvePath(const resolver::Request& req, resolver::Resolved& out);
        static bool resolveEntryForPath(const resolver::Request& req, resolver::Resolved& out);
        static bool enforcePermissions(const resolver::Request& req, resolver::Resolved& out);
        // A mutating action on a vault held as another server's copy is EROFS (mirror::access), after permissions.
        static bool enforceMirrorGate(const resolver::Request& req, resolver::Resolved& out);
        static bool resolveList(const resolver::Request& req, resolver::Resolved& out);
    };
}
