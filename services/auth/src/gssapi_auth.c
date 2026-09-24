#include "gssapi_auth.h"

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void log_gss_status(const char *label, OM_uint32 major, OM_uint32 minor)
{
    OM_uint32 msg_ctx = 0, min_stat;
    gss_buffer_desc msg;

    do {
        gss_display_status(&min_stat, major, GSS_C_GSS_CODE,
                            GSS_C_NO_OID, &msg_ctx, &msg);
        fprintf(stderr, "%s: %.*s\n", label, (int)msg.length, (char *)msg.value);
        gss_release_buffer(&min_stat, &msg);
    } while (msg_ctx != 0);

    msg_ctx = 0;
    do {
        gss_display_status(&min_stat, minor, GSS_C_MECH_CODE,
                            GSS_C_NO_OID, &msg_ctx, &msg);
        fprintf(stderr, "%s (mech): %.*s\n", label, (int)msg.length, (char *)msg.value);
        gss_release_buffer(&min_stat, &msg);
    } while (msg_ctx != 0);
}

int gssapi_auth_init(const char *keytab_path)
{
    /* GSSAPI reads the acceptor's keytab from this env var (or the default
     * keytab if unset). Setting it here keeps the keytab path an explicit
     * config value for the IdP rather than an ambient system setting. */
    if (setenv("KRB5_KTNAME", keytab_path, 1) != 0) {
        perror("gssapi_auth_init: setenv KRB5_KTNAME");
        return -1;
    }
    return 0;
}

int gssapi_auth_validate(const unsigned char *token, size_t token_len,
                          gssapi_auth_result_t *result)
{
    memset(result, 0, sizeof(*result));

    OM_uint32 major, minor;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc in_tok = { token_len, (void *)token };
    gss_buffer_desc out_tok = GSS_C_EMPTY_BUFFER;
    gss_name_t client_name = GSS_C_NO_NAME;

    /*
     * GSS_C_NO_CREDENTIAL as the acceptor cred makes GSSAPI pull whatever
     * service principal matches the token from the keytab set via
     * KRB5_KTNAME. That's correct as long as this process only ever
     * accepts for HTTP/idp.yourdomain.com -- if the IdP ever needs to
     * accept for multiple SPNEGO service principals, this needs an
     * explicit gss_acquire_cred() per principal instead.
     */
    major = gss_accept_sec_context(
        &minor,
        &ctx,
        GSS_C_NO_CREDENTIAL,
        &in_tok,
        GSS_C_NO_CHANNEL_BINDINGS,
        &client_name,
        NULL,           /* mech_type, unused */
        &out_tok,
        NULL,           /* ret_flags, unused */
        NULL,           /* time_rec, unused */
        NULL            /* delegated_cred_handle, unused */
    );

    if (out_tok.length > 0) {
        result->out_token = malloc(out_tok.length);
        if (result->out_token) {
            memcpy(result->out_token, out_tok.value, out_tok.length);
            result->out_token_len = out_tok.length;
        }
        gss_release_buffer(&minor, &out_tok);
    }

    if (GSS_ERROR(major)) {
        log_gss_status("gss_accept_sec_context", major, minor);
        if (ctx != GSS_C_NO_CONTEXT) {
            OM_uint32 tmp_minor;
            gss_delete_sec_context(&tmp_minor, &ctx, GSS_C_NO_BUFFER);
        }
        return -1;
    }

    if (major & GSS_S_CONTINUE_NEEDED) {
        /* Client needs to send another leg. Rare for a browser doing a
         * single SPNEGO/Kerberos exchange, but handle it honestly rather
         * than silently dropping it. Caller should 401 again with
         * result->out_token as the new WWW-Authenticate challenge. */
        result->authenticated = 0;
        return 0;
    }

    /* Full context established -- extract the principal name as text. */
    gss_buffer_desc name_buf = GSS_C_EMPTY_BUFFER;
    major = gss_display_name(&minor, client_name, &name_buf, NULL);
    if (GSS_ERROR(major)) {
        log_gss_status("gss_display_name", major, minor);
        gss_release_name(&minor, &client_name);
        gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);
        return -1;
    }

    snprintf(result->principal, sizeof(result->principal), "%.*s",
              (int)name_buf.length, (char *)name_buf.value);
    result->authenticated = 1;

    gss_release_buffer(&minor, &name_buf);
    gss_release_name(&minor, &client_name);
    gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);

    return 0;
}

void gssapi_auth_result_free(gssapi_auth_result_t *result)
{
    free(result->out_token);
    result->out_token = NULL;
    result->out_token_len = 0;
}