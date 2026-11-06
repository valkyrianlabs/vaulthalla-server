#include "platform/Sealer.hpp"
#include "platform/Durable.hpp"
#include "log/Registry.hpp"

#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <mutex>
#include <random>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <cstdlib>
#include <atomic>
#include <fcntl.h>
#include <thread>
#include <utility>
#include <paths.h>
#include <sodium.h>

using namespace std::string_literals;

namespace vh::platform::sealer {
    struct TctiSelection {
        std::string tctiConfig;
        std::string backend;
        std::string source;
    };

    struct EsysRuntime {
        ESYS_CONTEXT *esys{};
        TSS2_TCTI_CONTEXT *tcti{};
        std::string backend;
        std::string tctiConfig;
        std::string source;

        EsysRuntime() = default;
        EsysRuntime(const EsysRuntime &) = delete;
        EsysRuntime &operator=(const EsysRuntime &) = delete;
        EsysRuntime(EsysRuntime &&other) noexcept
            : esys(other.esys),
              tcti(other.tcti),
              backend(std::move(other.backend)),
              tctiConfig(std::move(other.tctiConfig)),
              source(std::move(other.source)) {
            other.esys = nullptr;
            other.tcti = nullptr;
        }
        EsysRuntime &operator=(EsysRuntime &&other) noexcept {
            if (this == &other) return *this;
            if (esys) Esys_Finalize(&esys);
            if (tcti) Tss2_TctiLdr_Finalize(&tcti);
            esys = other.esys;
            tcti = other.tcti;
            backend = std::move(other.backend);
            tctiConfig = std::move(other.tctiConfig);
            source = std::move(other.source);
            other.esys = nullptr;
            other.tcti = nullptr;
            return *this;
        }
        ~EsysRuntime() {
            if (esys) Esys_Finalize(&esys);
            if (tcti) Tss2_TctiLdr_Finalize(&tcti);
        }
    };

    static std::string describe_rc(const TSS2_RC rc) {
        std::ostringstream oss;
        oss << "rc=0x" << std::hex << std::uppercase << rc;
        if (const char *decoded = Tss2_RC_Decode(rc)) oss << " (" << decoded << ")";
        return oss.str();
    }

    static bool is_initialize_rc(const TSS2_RC rc) {
        return (rc & 0xFFFFu) == TPM2_RC_INITIALIZE;
    }

    // A failed TPM command, with its response code, so a caller can tell a full TPM from a broken blob.
    struct TpmError : std::runtime_error {
        TSS2_RC rc;
        TpmError(const std::string &what, const TSS2_RC code)
            : std::runtime_error(what + " " + describe_rc(code)), rc(code) {}
    };

    // TPM warnings that mean "busy or out of room right now", not "this blob or request is bad": out of transient object
    // or session slots, or asked to retry. Another process on the same TPM (tpm2-tools, a second daemon instance on a
    // shared swtpm) can cause them even while this process holds its own TPM lock.
    static bool is_transient_rc(const TSS2_RC rc) {
        switch (rc & 0xFFFFu) {
            case TPM2_RC_OBJECT_MEMORY:
            case TPM2_RC_SESSION_MEMORY:
            case TPM2_RC_MEMORY:
            case TPM2_RC_OBJECT_HANDLES:
            case TPM2_RC_SESSION_HANDLES:
            case TPM2_RC_RETRY:
            case TPM2_RC_YIELDED:
            case TPM2_RC_TESTING:
                return true;
            default:
                return false;
        }
    }

    // One TPM operation at a time in this process. swtpm (and many hardware TPMs) have three transient object slots,
    // and each seal/unseal holds two at once: the storage primary and the sealed object. The swtpm TCTI reconnects for
    // every command and nothing virtualizes handles (no resource manager on the socket), so commands of concurrent
    // operations interleave on the one TPM and their objects coexist: two unseals at once (DB pool connections; engines
    // loading vault keys; before #353 also the first request of every new S3 gateway connection, which unsealed
    // s3gw_master) need four slots and fail in Esys_Load with TPM_RC_OBJECT_MEMORY. Serialized, every
    // operation flushes its two objects before the next one creates any.
    static std::mutex &tpm_mutex() {
        static std::mutex m;
        return m;
    }

    constexpr int kTpmAttempts = 5;

    // Runs op (a whole seal or unseal: fresh ESYS context, objects created and flushed) under the TPM lock, and runs it
    // again, a bounded number of times, while it fails with a transient TPM warning from outside this process.
    template<class Op>
    static auto with_tpm(const char *what, Op &&op) {
        std::scoped_lock lock(tpm_mutex());
        auto backoff = std::chrono::milliseconds(50);
        for (int attempt = 1;; ++attempt) {
            try {
                return op();
            } catch (const TpmError &e) {
                if (!is_transient_rc(e.rc) || attempt >= kTpmAttempts) throw;
                log::Registry::crypto()->warn(
                    "[TPMKeyProvider] {} hit a transient TPM condition (attempt {}/{}): {}; retrying in {} ms",
                    what, attempt, kTpmAttempts, e.what(), backoff.count());
                std::this_thread::sleep_for(backoff);
                backoff *= 2;
            }
        }
    }

    static bool device_tpm_exists(const std::filesystem::path &p) {
        std::error_code ec;
        return std::filesystem::is_character_file(p, ec);
    }

    static bool local_port_open(const char *ip, const uint16_t port) {
        const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return false;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (::inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
            ::close(fd);
            return false;
        }

        const bool connected = (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
        ::close(fd);
        return connected;
    }

    static std::optional<std::string> env_override(const char *name) {
        const char *v = std::getenv(name);
        if (!v || v[0] == '\0') return std::nullopt;
        return std::string(v);
    }

    static TctiSelection select_tcti_backend() {
        if (const auto v = env_override("VH_TPM_TCTI")) {
            return {*v, "override", "VH_TPM_TCTI"};
        }
        if (const auto v = env_override("TSS2_TCTI")) {
            return {*v, "override", "TSS2_TCTI"};
        }
        if (const auto v = env_override("TPM2TOOLS_TCTI")) {
            return {*v, "override", "TPM2TOOLS_TCTI"};
        }
        if (device_tpm_exists("/dev/tpmrm0")) {
            return {"device:/dev/tpmrm0", "hardware", "auto-hardware"};
        }
        if (device_tpm_exists("/dev/tpm0")) {
            return {"device:/dev/tpm0", "hardware", "auto-hardware"};
        }
        if (local_port_open("127.0.0.1", 2321)) {
            return {"swtpm:host=127.0.0.1,port=2321", "swtpm", "auto-swtpm"};
        }

        throw std::runtime_error(
            "No TPM backend available: no /dev/tpmrm0 or /dev/tpm0, and managed swtpm is not reachable on 127.0.0.1:2321.");
    }

    static void ensure_tpm_started(ESYS_CONTEXT *ctx) {
        log::Registry::crypto()->info("[TPMKeyProvider] attempting TPM2_Startup(TPM2_SU_CLEAR)");
        const TSS2_RC rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
        if (rc == TSS2_RC_SUCCESS) {
            log::Registry::crypto()->info("[TPMKeyProvider] TPM2_Startup succeeded");
            return;
        }
        if (is_initialize_rc(rc)) {
            log::Registry::crypto()->info(
                "[TPMKeyProvider] TPM2_Startup returned initialize/already-started state ({}); continuing",
                describe_rc(rc));
            return;
        }
        throw std::runtime_error("Esys_Startup failed " + describe_rc(rc));
    }

    static EsysRuntime init_esys() {
        EsysRuntime runtime{};
        const auto selected = select_tcti_backend();
        runtime.backend = selected.backend;
        runtime.tctiConfig = selected.tctiConfig;
        runtime.source = selected.source;

        if (runtime.source == "auto-hardware") {
            log::Registry::crypto()->info(
                "[TPMKeyProvider] hardware TPM detected; using device TCTI {}",
                runtime.tctiConfig);
        } else if (runtime.source == "auto-swtpm") {
            log::Registry::crypto()->info(
                "[TPMKeyProvider] no hardware TPM detected; using managed swtpm TCTI {}",
                runtime.tctiConfig);
        } else {
            log::Registry::crypto()->info(
                "[TPMKeyProvider] honoring {} override with TCTI {}",
                runtime.source, runtime.tctiConfig);
        }

        TSS2_RC rc = Tss2_TctiLdr_Initialize(runtime.tctiConfig.c_str(), &runtime.tcti);
        if (rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error(
                "Tss2_TctiLdr_Initialize failed for TCTI '" + runtime.tctiConfig + "': " + describe_rc(rc));
        }

        rc = Esys_Initialize(&runtime.esys, runtime.tcti, nullptr);
        if (rc != TSS2_RC_SUCCESS) {
            throw std::runtime_error("Esys_Initialize failed: " + describe_rc(rc));
        }

        ensure_tpm_started(runtime.esys);
        return runtime;
    }

    static void flush_if_valid(ESYS_CONTEXT *ctx, ESYS_TR handle) {
        if (!ctx || handle == ESYS_TR_NONE) return;
        Esys_FlushContext(ctx, handle);
    }

    static std::vector<uint8_t> slurp(const std::filesystem::path &p) {
        std::ifstream f(p, std::ios::binary);
        return {std::istreambuf_iterator<char>(f), {}};
    }

    static void dump(const std::filesystem::path &p, const std::vector<uint8_t> &buf) {
        std::filesystem::create_directories(p.parent_path());
        std::ofstream f(p, std::ios::binary);
        f.write(reinterpret_cast<const char *>(buf.data()), static_cast<long>(buf.size()));
    }

    static ESYS_TR create_primary(ESYS_CONTEXT *ctx) {
        TPM2B_SENSITIVE_CREATE sens{};
        sens.size = 0; // no auth, no extra sensitive data

        TPM2B_PUBLIC pub{};
        pub.size = 0; // let marshalling figure it out
        pub.publicArea.type = TPM2_ALG_RSA;
        pub.publicArea.nameAlg = TPM2_ALG_SHA256;
        pub.publicArea.objectAttributes =
                TPMA_OBJECT_RESTRICTED
                | TPMA_OBJECT_DECRYPT
                | TPMA_OBJECT_FIXEDTPM
                | TPMA_OBJECT_FIXEDPARENT
                | TPMA_OBJECT_SENSITIVEDATAORIGIN // required here
                | TPMA_OBJECT_USERWITHAUTH
                | TPMA_OBJECT_NODA;

        pub.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
        pub.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
        pub.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
        pub.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
        pub.publicArea.parameters.rsaDetail.keyBits = 2048;
        pub.publicArea.parameters.rsaDetail.exponent = 0;

        TPM2B_DATA outside = {.size = 0, .buffer = {}};
        TPML_PCR_SELECTION pcr = {.count = 0, .pcrSelections = {}};

        ESYS_TR primHandle = ESYS_TR_NONE;
        TSS2_RC rc = Esys_CreatePrimary(
            ctx, ESYS_TR_RH_OWNER,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            &sens, &pub, &outside, &pcr,
            &primHandle, nullptr, nullptr, nullptr, nullptr);
        if (rc != TSS2_RC_SUCCESS) {
            log::Registry::crypto()->error("[TPMKeyProvider] CreatePrimary failed {}", describe_rc(rc));
            if (is_initialize_rc(rc)) {
                log::Registry::crypto()->error(
                    "[TPMKeyProvider] CreatePrimary indicates TPM initialize/startup state issue; verify selected backend and TPM2_Startup flow.");
            }
            throw TpmError("CreatePrimary failed", rc);
        }
        log::Registry::crypto()->info("[TPMKeyProvider] CreatePrimary succeeded");

        return primHandle;
    }

    std::string_view backend() noexcept { return "tpm2"; }

    // What the TCTI the daemon would pick is (the same order as select_tcti_backend), decided once per process.
    std::string_view posture() noexcept {
        static const std::string_view decided = [] {
            try {
                for (const char* var : {"VH_TPM_TCTI", "TSS2_TCTI", "TPM2TOOLS_TCTI"}) {
                    if (const auto v = env_override(var)) {
                        if (v->starts_with("device:")) return std::string_view("hardware");
                        if (v->starts_with("swtpm") || v->starts_with("mssim")) return std::string_view("software");
                        return std::string_view("unknown");
                    }
                }
                if (device_tpm_exists("/dev/tpmrm0") || device_tpm_exists("/dev/tpm0")) return std::string_view("hardware");
                return std::string_view("software");
            } catch (...) {
                return std::string_view("unknown");
            }
        }();
        return decided;
    }

    // ---- the PCR 7 policy (#351) ---------------------------------------------------------------------------------

    // PCR 7 of the SHA-256 bank: the secure-boot state (Secure Boot enabled, the PK/KEK/db/dbx contents, the
    // authorities that verified the boot).
    static TPML_PCR_SELECTION pcr7_selection() {
        TPML_PCR_SELECTION sel{};
        sel.count = 1;
        sel.pcrSelections[0].hash = TPM2_ALG_SHA256;
        sel.pcrSelections[0].sizeofSelect = 3;
        sel.pcrSelections[0].pcrSelect[0] = 0x80;  // PCR 7: bit 7 of byte 0
        return sel;
    }

    // Starts a trial or policy session and runs PolicyPCR over PCR 7 as it is now (an empty pcrDigest makes the TPM use
    // the current values). The caller flushes the session.
    static ESYS_TR start_pcr7_session(ESYS_CONTEXT *ctx, const TPM2_SE type) {
        ESYS_TR session = ESYS_TR_NONE;
        TPMT_SYM_DEF sym{};
        sym.algorithm = TPM2_ALG_NULL;
        TSS2_RC rc = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                           nullptr, type, &sym, TPM2_ALG_SHA256, &session);
        if (rc != TSS2_RC_SUCCESS) throw TpmError("Esys_StartAuthSession failed", rc);
        const auto sel = pcr7_selection();
        rc = Esys_PolicyPCR(ctx, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, nullptr, &sel);
        if (rc != TSS2_RC_SUCCESS) {
            flush_if_valid(ctx, session);
            throw TpmError("Esys_PolicyPCR failed", rc);
        }
        return session;
    }

    // The policy digest for PCR 7 at its current value: what a blob sealed now is bound to.
    static TPM2B_DIGEST current_pcr7_policy(ESYS_CONTEXT *ctx) {
        const ESYS_TR session = start_pcr7_session(ctx, TPM2_SE_TRIAL);
        TPM2B_DIGEST *digest = nullptr;
        const TSS2_RC rc = Esys_PolicyGetDigest(ctx, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &digest);
        flush_if_valid(ctx, session);
        if (rc != TSS2_RC_SUCCESS || !digest) throw TpmError("Esys_PolicyGetDigest failed", rc);
        const TPM2B_DIGEST out = *digest;
        Esys_Free(digest);
        return out;
    }

    // A policy failure is TPM_RC_POLICY_FAIL (format 1, error 0x1D), with the parameter or session number in the high bits.
    static bool is_policy_fail_rc(const TSS2_RC rc) {
        return (rc & 0x80u) != 0 && (rc & 0x3Fu) == 0x1Du;
    }

    static std::string policy_unsatisfied_message(const std::string &name) {
        return "The sealed secret '" + name + "' is bound to TPM PCR 7 (the secure-boot state), and PCR 7 no longer "
               "holds the value it was sealed under: the firmware, the Secure Boot keys or the boot configuration "
               "changed. It was not unsealed and nothing was regenerated. Recover one of two ways. (1) Boot the "
               "configuration it was sealed under (a recovery boot with the previous firmware or Secure Boot "
               "state), start Vaulthalla there and run `vh secret reseal` to bind the secrets to the new state, or "
               "set secrets.tpm_pcr_policy: none, restart and run `vh secret reseal` to turn the policy off. "
               "(2) Restore from the exports: the `vh secret export` files (`vh secret set`) and the vault key "
               "backups (`vh vault keys import`) under a new installation. Docs: "
               "vaults/secrets-and-key-export#firmware-and-secure-boot-updates.";
    }

    // ---- the blob files -------------------------------------------------------------------------------------------

    // Readers (unseal) share, whoever replaces a pair (a seal, a reseal's rename) holds it exclusively: a reader never
    // sees a new .pub beside an old .priv from this process.
    static std::shared_mutex &blob_mutex() {
        static std::shared_mutex m;
        return m;
    }

    // One reseal or recovery at a time per process.
    static std::mutex &reseal_mutex() {
        static std::mutex m;
        return m;
    }

    static std::atomic<ResealHook> &reseal_hook() {
        static std::atomic<ResealHook> hook{nullptr};
        return hook;
    }

    static void stage(const char *name) {
        if (const auto hook = reseal_hook().load()) hook(name);
    }

    static std::filesystem::path priv_path(const std::filesystem::path &dir, const std::string &name) {
        return dir / (name + ".priv");
    }

    static std::filesystem::path pub_path(const std::filesystem::path &dir, const std::string &name) {
        return dir / (name + ".pub");
    }

    static bool pair_exists(const std::filesystem::path &dir, const std::string &name) {
        std::error_code ec;
        return std::filesystem::exists(priv_path(dir, name), ec) && std::filesystem::exists(pub_path(dir, name), ec);
    }

    static void sync_path(const std::filesystem::path &p) {
        const int fd = ::open(p.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return;
        (void) platform::durable::sync(fd);
        ::close(fd);
    }

    static void sync_pair(const std::filesystem::path &dir, const std::string &name) {
        sync_path(priv_path(dir, name));
        sync_path(pub_path(dir, name));
        sync_path(dir);
    }

    static void remove_pair(const std::filesystem::path &dir, const std::string &name) {
        std::error_code ec;
        std::filesystem::remove(priv_path(dir, name), ec);
        std::filesystem::remove(pub_path(dir, name), ec);
    }

    // The public part is stored as the raw TPMT_PUBLIC the seal produced; this reads it back.
    static TPMT_PUBLIC read_public(const std::filesystem::path &dir, const std::string &name) {
        std::shared_lock files(blob_mutex());
        const auto buf = slurp(pub_path(dir, name));
        TPMT_PUBLIC pub{};
        if (buf.size() < sizeof(pub)) throw std::runtime_error("sealed TPM public blob is incomplete");
        memcpy(&pub, buf.data(), sizeof(pub));
        return pub;
    }

    // A KEYEDHASH object holding the secret under the TPM's storage primary, which is recreated on each use (no
    // persistent handle). The blob only loads into this TPM. Without a policy, whoever can read `dir` and reach the TPM
    // can unseal it. With Policy::Pcr7 the object has the digest of PolicyPCR over PCR 7 (as it is now) as its auth
    // policy and no password path (USERWITHAUTH off), so only a session that satisfies that policy unseals it.
    static void seal_once(const std::filesystem::path &dir, const std::string &name, const std::span<const uint8_t> secret,
                          const Policy policy) {
        auto runtime = init_esys();
        ESYS_TR parent = ESYS_TR_NONE;
        TPM2B_PRIVATE *outPriv = nullptr;
        TPM2B_PUBLIC *outPub = nullptr;

        try {
            parent = create_primary(runtime.esys);

            TPM2B_SENSITIVE_CREATE sens{};
            if (secret.size() > sizeof(sens.sensitive.data.buffer))
                throw std::runtime_error("secret '" + name + "' is too large to seal in the TPM (" +
                                         std::to_string(secret.size()) + " bytes, at most " +
                                         std::to_string(sizeof(sens.sensitive.data.buffer)) + ")");
            sens.size = 0;
            sens.sensitive.userAuth.size = 0;
            sens.sensitive.data.size = static_cast<UINT16>(secret.size());
            memcpy(sens.sensitive.data.buffer, secret.data(), secret.size());

            TPM2B_PUBLIC pub{};
            pub.size = 0;
            pub.publicArea.type = TPM2_ALG_KEYEDHASH;
            pub.publicArea.nameAlg = TPM2_ALG_SHA256;
            pub.publicArea.objectAttributes =
                    TPMA_OBJECT_FIXEDTPM |
                    TPMA_OBJECT_FIXEDPARENT |
                    TPMA_OBJECT_NODA;
            if (policy == Policy::Pcr7) {
                pub.publicArea.authPolicy = current_pcr7_policy(runtime.esys);
            } else {
                pub.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
            }
            pub.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
            pub.publicArea.unique.keyedHash.size = 0;

            TPM2B_DATA outsideInfo{};
            TPML_PCR_SELECTION pcrSel{};

            TSS2_RC rc = Esys_Create(runtime.esys, parent,
                                     ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                     &sens, &pub,
                                     &outsideInfo, &pcrSel,
                                     &outPriv, &outPub,
                                     nullptr, nullptr, nullptr);
            sodium_memzero(&sens, sizeof(sens));  // the secret's copy for the TPM command

            if (rc != TSS2_RC_SUCCESS) {
                throw TpmError("Esys_Create failed", rc);
            }

            std::unique_lock files(blob_mutex());
            dump(priv_path(dir, name), {outPriv->buffer, outPriv->buffer + outPriv->size});
            dump(pub_path(dir, name),
                 {
                     reinterpret_cast<uint8_t *>(&outPub->publicArea),
                     reinterpret_cast<uint8_t *>(&outPub->publicArea) + sizeof(outPub->publicArea)
                 });
        } catch (...) {
            if (outPriv) Esys_Free(outPriv);
            if (outPub) Esys_Free(outPub);
            flush_if_valid(runtime.esys, parent);
            throw;
        }

        if (outPriv) Esys_Free(outPriv);
        if (outPub) Esys_Free(outPub);
        flush_if_valid(runtime.esys, parent);

        log::Registry::crypto()->debug("[TPMKeyProvider] Sealed {} key to {} (policy {})", name, dir.string(),
                                       policyName(policy));
    }

    // ESAPI allocates the unsealed secret; zero it before handing the buffer back.
    static void wipe_free(TPM2B_SENSITIVE_DATA *data) noexcept {
        if (!data) return;
        sodium_memzero(data->buffer, sizeof(data->buffer));
        Esys_Free(data);
    }

    static std::vector<uint8_t> unseal_once(const std::filesystem::path &dir, const std::string &name) {
        std::vector<uint8_t> secret;
        auto runtime = init_esys();
        ESYS_TR parent = ESYS_TR_NONE;
        ESYS_TR obj = ESYS_TR_NONE;
        ESYS_TR session = ESYS_TR_NONE;
        TPM2B_SENSITIVE_DATA *outData = nullptr;

        try {
            parent = create_primary(runtime.esys); // recreate parent each boot

            TPM2B_PRIVATE inPriv{};
            std::shared_lock files(blob_mutex());
            auto privBuf = slurp(priv_path(dir, name));
            if (privBuf.size() > sizeof(inPriv.buffer)) {
                throw std::runtime_error("sealed TPM private blob is too large");
            }
            inPriv.size = static_cast<UINT16>(privBuf.size());
            memcpy(inPriv.buffer, privBuf.data(), privBuf.size());

            TPM2B_PUBLIC inPub{};
            auto pubBuf = slurp(pub_path(dir, name));
            if (pubBuf.size() < sizeof(inPub.publicArea)) {
                throw std::runtime_error("sealed TPM public blob is incomplete");
            }
            memcpy(&inPub.publicArea, pubBuf.data(), sizeof(inPub.publicArea));
            files.unlock();

            TSS2_RC rc = Esys_Load(runtime.esys, parent,
                                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                   &inPriv, &inPub, &obj);
            if (rc != TSS2_RC_SUCCESS) {
                throw TpmError("Esys_Load failed", rc);
            }

            // A blob with an auth policy (and no password path) unseals only through a session that satisfies it.
            const bool bound = inPub.publicArea.authPolicy.size != 0;
            if (bound) session = start_pcr7_session(runtime.esys, TPM2_SE_POLICY);
            rc = Esys_Unseal(runtime.esys, obj,
                             bound ? session : ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             &outData);
            if (rc != TSS2_RC_SUCCESS) {
                if (bound && is_policy_fail_rc(rc)) {
                    log::Registry::crypto()->error("[TPMKeyProvider] {} is bound to PCR 7, which no longer matches {}",
                                                   name, describe_rc(rc));
                    throw PolicyUnsatisfied(policy_unsatisfied_message(name));
                }
                throw TpmError("Esys_Unseal failed", rc);
            }

            secret.assign(outData->buffer, outData->buffer + outData->size);
        } catch (...) {
            wipe_free(outData);
            flush_if_valid(runtime.esys, session);
            flush_if_valid(runtime.esys, obj);
            flush_if_valid(runtime.esys, parent);
            throw;
        }

        wipe_free(outData);
        flush_if_valid(runtime.esys, session);
        flush_if_valid(runtime.esys, obj);
        flush_if_valid(runtime.esys, parent);

        log::Registry::crypto()->debug("[TPMKeyProvider] Unsealed master key from {}", dir.string());
        return secret;
    }

    void seal(const std::filesystem::path &dir, const std::string &name, const std::span<const uint8_t> secret,
              const Policy policy) {
        with_tpm("seal", [&] { seal_once(dir, name, secret, policy); });
    }

    std::vector<uint8_t> unseal(const std::filesystem::path &dir, const std::string &name) {
        return with_tpm("unseal", [&] { return unseal_once(dir, name); });
    }

    bool present(const std::filesystem::path &dir, const std::string &name) {
        return std::filesystem::exists(dir / (name + ".priv"));
    }

    bool complete(const std::filesystem::path &dir, const std::string &name) {
        const auto priv = dir / (name + ".priv");
        const auto pub = dir / (name + ".pub");
        return std::filesystem::exists(priv) && std::filesystem::exists(pub);
    }

    std::string_view policyName(const Policy policy) noexcept {
        return policy == Policy::Pcr7 ? "pcr7" : "none";
    }

    std::optional<Policy> parsePolicy(const std::string_view text) noexcept {
        if (text == "none") return Policy::None;
        if (text == "pcr7") return Policy::Pcr7;
        return std::nullopt;
    }

    bool policySupported() noexcept { return true; }

    Policy policyOf(const std::filesystem::path &dir, const std::string &name) {
        return read_public(dir, name).authPolicy.size != 0 ? Policy::Pcr7 : Policy::None;
    }

    void setResealHookForTesting(const ResealHook hook) noexcept { reseal_hook().store(hook); }

    static bool wiped_equal(std::vector<uint8_t> &a, std::vector<uint8_t> &b) {
        const bool same = a.size() == b.size() && (a.empty() || sodium_memcmp(a.data(), b.data(), a.size()) == 0);
        sodium_memzero(a.data(), a.size());
        sodium_memzero(b.data(), b.size());
        return same;
    }

    // Moves a pair over another (the live one), pub first. Callers hold the blob lock.
    static void move_pair(const std::filesystem::path &dir, const std::string &from, const std::string &to,
                          const bool hooks = false) {
        std::filesystem::rename(pub_path(dir, from), pub_path(dir, to));
        if (hooks) stage("pub_replaced");
        std::filesystem::rename(priv_path(dir, from), priv_path(dir, to));
        if (hooks) stage("priv_replaced");
    }

    static void copy_pair(const std::filesystem::path &dir, const std::string &from, const std::string &to) {
        std::filesystem::copy_file(priv_path(dir, from), priv_path(dir, to),
                                   std::filesystem::copy_options::overwrite_existing);
        std::filesystem::copy_file(pub_path(dir, from), pub_path(dir, to),
                                   std::filesystem::copy_options::overwrite_existing);
        sync_pair(dir, to);
    }

    static void recover_locked(const std::filesystem::path &dir, const std::string &name) {
        const std::string staged = name + ".staged", prev = name + ".prev";
        std::error_code ec;
        const bool anyStaged = std::filesystem::exists(priv_path(dir, staged), ec) ||
                               std::filesystem::exists(pub_path(dir, staged), ec);
        const bool anyPrev = std::filesystem::exists(priv_path(dir, prev), ec) ||
                             std::filesystem::exists(pub_path(dir, prev), ec);
        if (!anyStaged && !anyPrev) return;

        bool liveOk = false;
        if (pair_exists(dir, name)) {
            try {
                auto secret = unseal(dir, name);
                sodium_memzero(secret.data(), secret.size());
                liveOk = true;
            } catch (const PolicyUnsatisfied &) {
                // Can't tell a good pair from a torn one while PCR 7 is off; leave every file as it is.
                return;
            } catch (const TpmError &e) {
                // The TPM refused this blob (it doesn't load: a torn pair). Any other failure (the TPM not reachable,
                // CreatePrimary) says nothing about the files, so they stay.
                const std::string what = e.what();
                if (!what.starts_with("Esys_Load failed") && !what.starts_with("Esys_Unseal failed")) return;
            } catch (const std::runtime_error &e) {
                if (std::string(e.what()).find("public blob is incomplete") == std::string::npos &&
                    std::string(e.what()).find("private blob is too large") == std::string::npos)
                    return;
            }
        }

        std::unique_lock files(blob_mutex());
        if (liveOk) {
            log::Registry::crypto()->info("[Sealer] '{}': finishing an interrupted reseal (the live blob is intact)", name);
        } else if (pair_exists(dir, prev)) {
            log::Registry::crypto()->warn("[Sealer] '{}': an interrupted reseal left a torn blob; restoring the previous "
                                          "one", name);
            move_pair(dir, prev, name);
            sync_pair(dir, name);
        } else if (pair_exists(dir, staged)) {
            log::Registry::crypto()->warn("[Sealer] '{}': an interrupted reseal left no usable live blob; installing the "
                                          "staged one", name);
            move_pair(dir, staged, name);
            sync_pair(dir, name);
        }
        remove_pair(dir, staged);
        remove_pair(dir, prev);
        sync_path(dir);
    }

    void recover(const std::filesystem::path &dir, const std::string &name) {
        std::scoped_lock lock(reseal_mutex());
        recover_locked(dir, name);
    }

    ResealResult reseal(const std::filesystem::path &dir, const std::string &name, const Policy to) {
        std::scoped_lock lock(reseal_mutex());
        stage("begin");
        recover_locked(dir, name);
        if (!pair_exists(dir, name)) throw std::runtime_error("no sealed secret '" + name + "' under " + dir.string());

        const auto from = policyOf(dir, name);
        std::vector<uint8_t> secret = unseal(dir, name);  // PolicyUnsatisfied when PCR 7 no longer matches
        struct Wipe {
            std::vector<uint8_t> &v;
            ~Wipe() { sodium_memzero(v.data(), v.size()); }
        } wipe{secret};

        if (from == to) {
            if (to == Policy::None) return {from, to, false};
            const auto pub = read_public(dir, name);
            const auto now = with_tpm("policy", [&] {
                auto runtime = init_esys();
                return current_pcr7_policy(runtime.esys);
            });
            if (now.size == pub.authPolicy.size && std::memcmp(now.buffer, pub.authPolicy.buffer, now.size) == 0)
                return {from, to, false};
        }

        const std::string staged = name + ".staged", prev = name + ".prev";
        seal(dir, staged, secret, to);
        stage("staged");
        {
            sync_pair(dir, staged);
            auto back = unseal(dir, staged);
            auto want = secret;
            if (!wiped_equal(back, want)) {
                remove_pair(dir, staged);
                throw std::runtime_error("the resealed '" + name + "' did not unseal to the secret that was sealed; the "
                                         "existing blob is untouched");
            }
        }
        stage("verified");

        {
            std::unique_lock files(blob_mutex());
            copy_pair(dir, name, prev);
            stage("prev_kept");
            move_pair(dir, staged, name, true);
            sync_pair(dir, name);
        }

        {
            auto live = unseal(dir, name);
            auto want = secret;
            if (!wiped_equal(live, want)) {
                std::unique_lock files(blob_mutex());
                move_pair(dir, prev, name);
                sync_pair(dir, name);
                throw std::runtime_error("the resealed '" + name + "' did not unseal to the secret that was sealed; "
                                         "the previous blob was restored");
            }
        }
        stage("installed");
        {
            std::unique_lock files(blob_mutex());
            remove_pair(dir, prev);
            sync_path(dir);
        }
        stage("done");
        log::Registry::crypto()->info("[Sealer] Resealed '{}': policy {} -> {}", name, policyName(from), policyName(to));
        return {from, to, true};
    }
} // namespace vh::platform::sealer
