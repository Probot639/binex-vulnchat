#ifndef SAML_ASSERTION_H
#define SAML_ASSERTION_H

/*
 * This is the whole contract between the HTTP/Kerberos layer and the SAML
 * core: give it a validated principal + the target SP, get back signed XML.
 * Nothing above this layer should touch libxml2/xmlsec1 directly.
 */

/* Call once at process startup, before any signing happens. */
int saml_assertion_init(const char *idp_entity_id,
                         const char *signing_key_path,   /* PEM private key */
                         const char *signing_cert_path);  /* PEM cert */

void saml_assertion_shutdown(void);

/*
 * Builds a signed <samlp:Response> asserting that `principal` authenticated
 * (via Kerberos) to `sp_entity_id`, to be POSTed to `acs_url`.
 *
 * On success, *out_xml is a malloc'd, NUL-terminated XML string the caller
 * must free(); returns 0. Returns -1 on failure.
 */
int saml_build_and_sign_response(const char *principal,
                                  const char *sp_entity_id,
                                  const char *acs_url,
                                  char **out_xml);

#endif /* SAML_ASSERTION_H */