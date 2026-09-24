// IdP HTTPS front door.
//
// Deliberately thin: parse HTTP, drive the Negotiate/SPNEGO handshake,
// call into the C core (gssapi_auth.*, saml_assertion.*, sp_registry.*),
// and write the response. No XML or crypto logic lives in this file.
//
// Built against libmicrohttpd. Link with -lmicrohttpd -lssl -lcrypto.

#include <microhttpd.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "gssapi_auth.h"
#include "saml_assertion.h"
#include "sp_registry.h"
}

namespace {

constexpr size_t kMaxSps = 64;
sp_record_t g_sps[kMaxSps];
int g_sp_count = 0;

// --- minimal base64 (self-contained, no extra dependency beyond libc) ---

std::string base64_encode(const unsigned char *data, size_t len) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= len) {
        unsigned v = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out += tbl[(v >> 18) & 0x3F];
        out += tbl[(v >> 12) & 0x3F];
        out += tbl[(v >> 6) & 0x3F];
        out += tbl[v & 0x3F];
        i += 3;
    }
    size_t rem = len - i;
    if (rem == 1) {
        unsigned v = data[i] << 16;
        out += tbl[(v >> 18) & 0x3F];
        out += tbl[(v >> 12) & 0x3F];
        out += "==";
    } else if (rem == 2) {
        unsigned v = (data[i] << 16) | (data[i + 1] << 8);
        out += tbl[(v >> 18) & 0x3F];
        out += tbl[(v >> 12) & 0x3F];
        out += tbl[(v >> 6) & 0x3F];
        out += '=';
    }
    return out;
}

std::vector<unsigned char> base64_decode(const std::string &in) {
    static int tbl[256];
    static bool init = false;
    if (!init) {
        std::fill(std::begin(tbl), std::end(tbl), -1);
        const char *chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; i++) tbl[(unsigned char)chars[i]] = i;
        init = true;
    }

    std::vector<unsigned char> out;
    int val = 0, bits = -8;
    for (unsigned char c : in) {
        if (tbl[c] == -1) break;
        val = (val << 6) + tbl[c];
        bits += 6;
        if (bits >= 0) {
            out.push_back((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return out;
}

// Builds the HTTP-POST binding auto-submit page.
std::string build_post_binding_html(const std::string &acs_url,
                                     const std::string &saml_response_b64) {
    // NOTE: acs_url/saml_response_b64 are attacker-influenced only insofar
    // as sp_entity_id/acs_url come from your own sp_registry (trusted) and
    // saml_response_b64 is our own signed output -- so no HTML-escaping
    // gap here. If a query-string-supplied RelayState is ever echoed into
    // this page, that value MUST be HTML-escaped before landing here.
    std::string html =
        "<!DOCTYPE html><html><body onload=\"document.forms[0].submit()\">"
        "<form method=\"POST\" action=\"" + acs_url + "\">"
        "<input type=\"hidden\" name=\"SAMLResponse\" value=\"" + saml_response_b64 + "\"/>"
        "<noscript><input type=\"submit\" value=\"Continue\"/></noscript>"
        "</form></body></html>";
    return html;
}

MHD_Result send_text(MHD_Connection *conn, unsigned int status,
                      const std::string &body, const char *content_type) {
    MHD_Response *resp = MHD_create_response_from_buffer(
        body.size(), (void *)body.data(), MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(resp, "Content-Type", content_type);
    MHD_Result ret = MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp);
    return ret;
}

MHD_Result send_negotiate_challenge(MHD_Connection *conn,
                                     const unsigned char *out_token,
                                     size_t out_token_len) {
    MHD_Response *resp = MHD_create_response_from_buffer(0, nullptr, MHD_RESPMEM_PERSISTENT);
    std::string header = "Negotiate";
    if (out_token && out_token_len > 0) {
        header += " " + base64_encode(out_token, out_token_len);
    }
    MHD_add_response_header(resp, "WWW-Authenticate", header.c_str());
    MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_UNAUTHORIZED, resp);
    MHD_destroy_response(resp);
    return ret;
}

// GET /sso?sp=<entity_id>
//
// TODO: this reads the target SP from a plain `sp` query param rather than
// decoding a real deflated/base64 SAMLRequest (HTTP-Redirect binding).
// That's enough to prove the Kerberos -> signed-assertion path end to end;
// swap in real AuthnRequest parsing (zlib inflate + libxml2) once SP-side
// AuthnRequest signing is in scope -- see NOTES.md.
MHD_Result handle_sso(MHD_Connection *conn, const char *sp_name) {
    const sp_record_t *sp = sp_registry_find(g_sps, g_sp_count, sp_name);
    if (!sp) {
        return send_text(conn, MHD_HTTP_BAD_REQUEST,
                          "unknown SP: " + std::string(sp_name), "text/plain");
    }

    const char *auth_header =
        MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");

    const std::string prefix = "Negotiate ";
    if (!auth_header || strncmp(auth_header, prefix.c_str(), prefix.size()) != 0) {
        // No token yet -- challenge the client.
        return send_negotiate_challenge(conn, nullptr, 0);
    }

    std::vector<unsigned char> token = base64_decode(auth_header + prefix.size());

    gssapi_auth_result_t result;
    if (gssapi_auth_validate(token.data(), token.size(), &result) != 0) {
        return send_text(conn, MHD_HTTP_UNAUTHORIZED,
                          "Kerberos authentication failed", "text/plain");
    }

    if (!result.authenticated) {
        // Multi-leg negotiate -- send the continuation token back.
        MHD_Result ret = send_negotiate_challenge(conn, result.out_token, result.out_token_len);
        gssapi_auth_result_free(&result);
        return ret;
    }

    char acs_url[600];
    sp_registry_acs_url(sp, acs_url, sizeof(acs_url));

    char *signed_xml = nullptr;
    int rc = saml_build_and_sign_response(result.principal, sp->name, acs_url, &signed_xml);
    gssapi_auth_result_free(&result);

    if (rc != 0 || !signed_xml) {
        return send_text(conn, MHD_HTTP_INTERNAL_SERVER_ERROR,
                          "failed to build SAML assertion", "text/plain");
    }

    std::string xml_str(signed_xml);
    free(signed_xml);

    std::string b64 = base64_encode(
        reinterpret_cast<const unsigned char *>(xml_str.data()), xml_str.size());
    std::string html = build_post_binding_html(acs_url, b64);

    return send_text(conn, MHD_HTTP_OK, html, "text/html");
}

MHD_Result request_handler(void *, MHD_Connection *conn, const char *url,
                            const char *method, const char *, const char *,
                            size_t *, void **con_cls) {
    // libmicrohttpd calls the handler twice per request; only act on the
    // second call (con_cls is non-null after the first).
    static int dummy;
    if (*con_cls == nullptr) {
        *con_cls = &dummy;
        return MHD_YES;
    }

    if (strcmp(method, "GET") != 0) {
        return send_text(conn, MHD_HTTP_METHOD_NOT_ALLOWED, "", "text/plain");
    }

    if (strcmp(url, "/sso") == 0) {
        const char *sp_name = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "sp");
        if (!sp_name) {
            return send_text(conn, MHD_HTTP_BAD_REQUEST, "missing ?sp=", "text/plain");
        }
        return handle_sso(conn, sp_name);
    }

    return send_text(conn, MHD_HTTP_NOT_FOUND, "not found", "text/plain");
}

}  // namespace

// Called from main.cpp. Returns 0 on success; the returned MHD_Daemon* is
// owned by the caller (stop it with MHD_stop_daemon at shutdown).
//
// TODO(wiring): main.cpp needs to call this after kdc.c's own startup, and
// needs to supply real paths -- see NOTES.md for exactly what I need from
// main.cpp/kdc.c to fill these in for real rather than as placeholders.
extern "C" struct MHD_Daemon *idp_http_server_start(
    int port,
    const char *tls_cert_path, const char *tls_key_path,
    const char *sp_dir,
    const char *idp_entity_id,
    const char *signing_key_path, const char *signing_cert_path,
    const char *keytab_path) {

    g_sp_count = sp_registry_load(sp_dir, g_sps, kMaxSps);
    if (g_sp_count < 0) {
        fprintf(stderr, "idp_http_server_start: failed to load SP registry from %s\n", sp_dir);
        return nullptr;
    }

    if (gssapi_auth_init(keytab_path) != 0) {
        fprintf(stderr, "idp_http_server_start: gssapi_auth_init failed\n");
        return nullptr;
    }

    if (saml_assertion_init(idp_entity_id, signing_key_path, signing_cert_path) != 0) {
        fprintf(stderr, "idp_http_server_start: saml_assertion_init failed\n");
        return nullptr;
    }

    // TODO: load tls_cert_path/tls_key_path file contents and pass via
    // MHD_OPTION_HTTPS_MEM_CERT / MHD_OPTION_HTTPS_MEM_KEY. Left as a stub
    // (plain HTTP daemon) pending a decision on how the IdP's TLS cert is
    // generated/stored -- likely alongside the SAML signing cert under
    // keys/idp_signing/, but flagging rather than assuming.
    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_THREAD_PER_CONNECTION | MHD_USE_INTERNAL_POLLING_THREAD,
        port, nullptr, nullptr,
        &request_handler, nullptr,
        MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "idp_http_server_start: MHD_start_daemon failed\n");
        return nullptr;
    }

    fprintf(stderr, "IdP SSO endpoint listening on port %d (TLS: TODO)\n", port);
    return daemon;
}