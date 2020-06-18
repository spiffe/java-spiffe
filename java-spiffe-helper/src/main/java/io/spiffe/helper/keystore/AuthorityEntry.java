package io.spiffe.helper.keystore;

import lombok.Builder;
import lombok.Value;

import java.security.cert.X509Certificate;

@Value
class AuthorityEntry {
    String alias;
    X509Certificate certificate;

    @Builder
    AuthorityEntry(
            final String alias,
            final X509Certificate certificate) {
        this.alias = alias;
        this.certificate = certificate;
    }
}
