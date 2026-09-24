#include "saml_assertion.h"

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uuid/uuid.h>

static char g_idp_entity_id[256];
static char g_signing_key_path[512];
static char g_signing_cert_path[512];

int saml_assertion_init(const char *idp_entity_id,
                         const char *signing_key_path,
                         const char *signing_cert_path)
{
    snprintf(g_idp_entity_id, sizeof(g_idp_entity_id), "%s", idp_entity_id);
    snprintf(g_signing_key_path, sizeof(g_signing_key_path), "%s", signing_key_path);
    snprintf(g_signing_cert_path, sizeof(g_signing_cert_path), "%s", signing_cert_path);

    xmlInitParser();

    if (xmlSecInit() < 0) {
        fprintf(stderr, "saml_assertion_init: xmlSecInit failed\n");
        return -1;
    }
    if (xmlSecCryptoAppInit(NULL) < 0) {
        fprintf(stderr, "saml_assertion_init: xmlSecCryptoAppInit failed\n");
        return -1;
    }
    if (xmlSecCryptoInit() < 0) {
        fprintf(stderr, "saml_assertion_init: xmlSecCryptoInit failed\n");
        return -1;
    }
    return 0;
}

void saml_assertion_shutdown(void)
{
    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    xmlCleanupParser();
}

static void gen_id(char *buf, size_t buflen, const char *prefix)
{
    uuid_t u;
    char uustr[37];
    uuid_generate_random(u);
    uuid_unparse_lower(u, uustr);
    /* SAML IDs must not start with a digit -- our prefix (e.g. "_") handles that. */
    snprintf(buf, buflen, "%s%s", prefix, uustr);
}

static void iso8601_now(char *buf, size_t buflen)
{
    time_t t = time(NULL);
    struct tm tm_utc;
    gmtime_r(&t, &tm_utc);
    strftime(buf, buflen, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

/*
 * Builds the unsigned Response/Assertion XML as text. Kept deliberately as
 * one template string rather than built node-by-node with libxml2 calls --
 * easier to eyeball against the SAML core spec, at the cost of being pickier
 * about escaping `principal`/`sp_entity_id` if they ever contain XML
 * metacharacters. Both come from trusted sources here (a Kerberos principal
 * from GSSAPI, and sp_entity_id from your own SP registry) so this is fine
 * as-is; treat it as a TODO if either input path ever becomes less trusted.
 */
static char *build_response_xml(const char *principal,
                                 const char *sp_entity_id,
                                 const char *acs_url,
                                 const char *response_id,
                                 const char *assertion_id,
                                 const char *issue_instant,
                                 const char *not_on_or_after)
{
    const char *tmpl =
        "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n"
        "    xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n"
        "    ID=\"%s\" Version=\"2.0\" IssueInstant=\"%s\"\n"
        "    Destination=\"%s\">\n"
        "  <saml:Issuer>%s</saml:Issuer>\n"
        "  <samlp:Status>\n"
        "    <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>\n"
        "  </samlp:Status>\n"
        "  <saml:Assertion ID=\"%s\" Version=\"2.0\" IssueInstant=\"%s\">\n"
        "    <saml:Issuer>%s</saml:Issuer>\n"
        "    <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/>\n"
        "    <saml:Subject>\n"
        "      <saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">%s</saml:NameID>\n"
        "      <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n"
        "        <saml:SubjectConfirmationData Recipient=\"%s\" NotOnOrAfter=\"%s\"/>\n"
        "      </saml:SubjectConfirmation>\n"
        "    </saml:Subject>\n"
        "    <saml:Conditions NotOnOrAfter=\"%s\">\n"
        "      <saml:AudienceRestriction>\n"
        "        <saml:Audience>%s</saml:Audience>\n"
        "      </saml:AudienceRestriction>\n"
        "    </saml:Conditions>\n"
        "    <saml:AuthnStatement AuthnInstant=\"%s\">\n"
        "      <saml:AuthnContext>\n"
        "        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos</saml:AuthnContextClassRef>\n"
        "      </saml:AuthnContext>\n"
        "    </saml:AuthnStatement>\n"
        "  </saml:Assertion>\n"
        "</samlp:Response>\n";

    /* Generous fixed buffer -- all inputs are short (IDs, entity IDs, a
     * principal, a URL). Revisit with dynamic sizing if that stops holding. */
    size_t bufsize = strlen(tmpl) + 4096;
    char *out = malloc(bufsize);
    if (!out)
        return NULL;

    snprintf(out, bufsize, tmpl,
              response_id, issue_instant, acs_url,
              g_idp_entity_id,
              assertion_id, issue_instant,
              g_idp_entity_id,
              principal,
              acs_url, not_on_or_after,
              not_on_or_after,
              sp_entity_id,
              issue_instant);

    return out;
}

/* Loads the signing key + cert into a signature context and signs the
 * ds:Signature template node inside the Assertion (enveloped signature). */
static int sign_assertion(xmlDocPtr doc)
{
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root)
        return -1;

    /* Find the ds:Signature placeholder we left inside saml:Assertion. */
    xmlNodePtr sig_node = xmlSecFindNode(root, xmlSecNodeSignature, xmlSecDSigNs);
    if (!sig_node) {
        fprintf(stderr, "sign_assertion: no ds:Signature node found\n");
        return -1;
    }

    xmlSecDSigCtxPtr dsig_ctx = xmlSecDSigCtxCreate(NULL);
    if (!dsig_ctx) {
        fprintf(stderr, "sign_assertion: xmlSecDSigCtxCreate failed\n");
        return -1;
    }

    dsig_ctx->signKey = xmlSecCryptoAppKeyLoad(
        g_signing_key_path, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    if (!dsig_ctx->signKey) {
        fprintf(stderr, "sign_assertion: failed to load signing key from %s\n",
                g_signing_key_path);
        xmlSecDSigCtxDestroy(dsig_ctx);
        return -1;
    }

    if (xmlSecCryptoAppKeyCertLoad(dsig_ctx->signKey, g_signing_cert_path,
                                    xmlSecKeyDataFormatPem) < 0) {
        fprintf(stderr, "sign_assertion: failed to load signing cert from %s\n",
                g_signing_cert_path);
        xmlSecDSigCtxDestroy(dsig_ctx);
        return -1;
    }

    int rc = 0;
    if (xmlSecDSigCtxSign(dsig_ctx, sig_node) < 0) {
        fprintf(stderr, "sign_assertion: xmlSecDSigCtxSign failed\n");
        rc = -1;
    }

    xmlSecDSigCtxDestroy(dsig_ctx);
    return rc;
}

/*
 * NOTE on the Signature template: xmlsec1's usual pattern is to build the
 * ds:Signature/SignedInfo/Reference/Transform tree with
 * xmlSecTmplSignatureCreate()+xmlSecTmplSignatureAddReference() rather than
 * hand-writing a bare `<ds:Signature/>` and hoping xmlSecDSigCtxSign fills
 * it in -- an empty placeholder like the one in build_response_xml() is NOT
 * enough on its own. This function replaces that placeholder with a proper
 * template before signing. Kept separate from build_response_xml so the
 * "what goes in the assertion" text and "how it gets wrapped for signing"
 * logic don't tangle together.
 */
static int install_signature_template(xmlDocPtr doc, const char *assertion_id)
{
    xmlNodePtr root = xmlDocGetRootElement(doc);
    xmlNodePtr old_sig = xmlSecFindNode(root, xmlSecNodeSignature, xmlSecDSigNs);
    if (!old_sig)
        return -1;
    xmlNodePtr assertion_node = old_sig->parent;

    xmlNodePtr new_sig = xmlSecTmplSignatureCreate(
        doc, xmlSecTransformExclC14NId, xmlSecTransformRsaSha256Id, NULL);
    if (!new_sig)
        return -1;

    char uri[300];
    snprintf(uri, sizeof(uri), "#%s", assertion_id);

    xmlNodePtr ref = xmlSecTmplSignatureAddReference(
        new_sig, xmlSecTransformSha256Id, NULL, (xmlChar *)uri, NULL);
    if (!ref)
        return -1;

    xmlSecTmplReferenceAddTransform(ref, xmlSecTransformEnvelopedId);
    xmlSecTmplReferenceAddTransform(ref, xmlSecTransformExclC14NId);

    xmlNodePtr key_info = xmlSecTmplSignatureEnsureKeyInfo(new_sig, NULL);
    xmlSecTmplKeyInfoAddX509Data(key_info);

    xmlReplaceNode(old_sig, new_sig);
    xmlFreeNode(old_sig);

    return 0;
}

int saml_build_and_sign_response(const char *principal,
                                  const char *sp_entity_id,
                                  const char *acs_url,
                                  char **out_xml)
{
    char response_id[64], assertion_id[64];
    char issue_instant[32], not_on_or_after[32];

    gen_id(response_id, sizeof(response_id), "_");
    gen_id(assertion_id, sizeof(assertion_id), "_");
    iso8601_now(issue_instant, sizeof(issue_instant));

    /* 5 minute assertion validity window -- adjust to taste. */
    time_t exp = time(NULL) + 300;
    struct tm tm_exp;
    gmtime_r(&exp, &tm_exp);
    strftime(not_on_or_after, sizeof(not_on_or_after), "%Y-%m-%dT%H:%M:%SZ", &tm_exp);

    char *xml_text = build_response_xml(principal, sp_entity_id, acs_url,
                                          response_id, assertion_id,
                                          issue_instant, not_on_or_after);
    if (!xml_text)
        return -1;

    xmlDocPtr doc = xmlReadMemory(xml_text, (int)strlen(xml_text),
                                   NULL, "UTF-8", XML_PARSE_NONET);
    free(xml_text);
    if (!doc) {
        fprintf(stderr, "saml_build_and_sign_response: failed to parse built XML\n");
        return -1;
    }

    if (install_signature_template(doc, assertion_id) < 0) {
        fprintf(stderr, "saml_build_and_sign_response: install_signature_template failed\n");
        xmlFreeDoc(doc);
        return -1;
    }

    if (sign_assertion(doc) < 0) {
        xmlFreeDoc(doc);
        return -1;
    }

    xmlChar *dumped = NULL;
    int dumped_len = 0;
    xmlDocDumpFormatMemory(doc, &dumped, &dumped_len, 0);
    xmlFreeDoc(doc);

    if (!dumped)
        return -1;

    *out_xml = strdup((char *)dumped);
    xmlFree(dumped);

    return *out_xml ? 0 : -1;
}