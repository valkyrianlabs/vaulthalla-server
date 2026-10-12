#include "platform/Sealer.hpp"
#include "log/Registry.hpp"

#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <cstdlib>
#include <utility>
#include <paths.h>

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
            throw std::runtime_error("CreatePrimary failed " + describe_rc(rc));
        }
        log::Registry::crypto()->info("[TPMKeyProvider] CreatePrimary succeeded");

        return primHandle;
    }

    std::string_view backend() noexcept { return "tpm2"; }

    // A KEYEDHASH object holding the secret under the TPM's storage primary, which is recreated on each use (no
    // persistent handle). The blob only loads into this TPM. No PCR policy: whoever can read `dir` and reach the TPM
    // can unseal it.
    void seal(const std::filesystem::path &dir, const std::string &name, const std::vector<uint8_t> &secret) {
        auto runtime = init_esys();
        ESYS_TR parent = ESYS_TR_NONE;
        TPM2B_PRIVATE *outPriv = nullptr;
        TPM2B_PUBLIC *outPub = nullptr;

        try {
            parent = create_primary(runtime.esys);

            TPM2B_SENSITIVE_CREATE sens{};
            sens.size = 0;
            sens.sensitive.userAuth.size = 0;
            sens.sensitive.data.size = secret.size();
            memcpy(sens.sensitive.data.buffer, secret.data(), secret.size());

            TPM2B_PUBLIC pub{};
            pub.size = 0;
            pub.publicArea.type = TPM2_ALG_KEYEDHASH;
            pub.publicArea.nameAlg = TPM2_ALG_SHA256;
            pub.publicArea.objectAttributes =
                    TPMA_OBJECT_FIXEDTPM |
                    TPMA_OBJECT_FIXEDPARENT |
                    TPMA_OBJECT_USERWITHAUTH |
                    TPMA_OBJECT_NODA;
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

            if (rc != TSS2_RC_SUCCESS) {
                throw std::runtime_error("Esys_Create failed " + describe_rc(rc));
            }

            dump(dir / (name + ".priv"), {outPriv->buffer, outPriv->buffer + outPriv->size});
            dump(dir / (name + ".pub"),
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

        log::Registry::crypto()->debug("[TPMKeyProvider] Sealed {} key to {}", name, dir.string());
    }

    std::vector<uint8_t> unseal(const std::filesystem::path &dir, const std::string &name) {
        std::vector<uint8_t> secret;
        auto runtime = init_esys();
        ESYS_TR parent = ESYS_TR_NONE;
        ESYS_TR obj = ESYS_TR_NONE;
        TPM2B_SENSITIVE_DATA *outData = nullptr;

        try {
            parent = create_primary(runtime.esys); // recreate parent each boot

            TPM2B_PRIVATE inPriv{};
            auto privBuf = slurp(dir / (name + ".priv"));
            if (privBuf.size() > sizeof(inPriv.buffer)) {
                throw std::runtime_error("sealed TPM private blob is too large");
            }
            inPriv.size = static_cast<UINT16>(privBuf.size());
            memcpy(inPriv.buffer, privBuf.data(), privBuf.size());

            TPM2B_PUBLIC inPub{};
            auto pubBuf = slurp(dir / (name + ".pub"));
            if (pubBuf.size() < sizeof(inPub.publicArea)) {
                throw std::runtime_error("sealed TPM public blob is incomplete");
            }
            memcpy(&inPub.publicArea, pubBuf.data(), sizeof(inPub.publicArea));

            TSS2_RC rc = Esys_Load(runtime.esys, parent,
                                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                   &inPriv, &inPub, &obj);
            if (rc != TSS2_RC_SUCCESS) {
                throw std::runtime_error("Esys_Load failed " + describe_rc(rc));
            }

            rc = Esys_Unseal(runtime.esys, obj,
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             &outData);
            if (rc != TSS2_RC_SUCCESS) {
                throw std::runtime_error("Esys_Unseal failed " + describe_rc(rc));
            }

            secret.assign(outData->buffer, outData->buffer + outData->size);
        } catch (...) {
            if (outData) Esys_Free(outData);
            flush_if_valid(runtime.esys, obj);
            flush_if_valid(runtime.esys, parent);
            throw;
        }

        if (outData) Esys_Free(outData);
        flush_if_valid(runtime.esys, obj);
        flush_if_valid(runtime.esys, parent);

        log::Registry::crypto()->debug("[TPMKeyProvider] Unsealed master key from {}", dir.string());
        return secret;
    }

    bool present(const std::filesystem::path &dir, const std::string &name) {
        return std::filesystem::exists(dir / (name + ".priv"));
    }

    bool complete(const std::filesystem::path &dir, const std::string &name) {
        const auto priv = dir / (name + ".priv");
        const auto pub = dir / (name + ".pub");
        return std::filesystem::exists(priv) && std::filesystem::exists(pub);
    }
} // namespace vh::platform::sealer
