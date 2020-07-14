package io.spiffe.helper.keystore;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Data;
import lombok.Setter;

import java.security.Key;
import java.security.cert.X509Certificate;

@Data
class PrivateKeyEntry {

    @Setter(AccessLevel.NONE)
    private String alias;

    @Setter(AccessLevel.NONE)
    private Key privateKey;

    @Setter(AccessLevel.NONE)
    private String password;

    @Setter(AccessLevel.NONE)
    private X509Certificate[] certificateChain;

    @Builder
    PrivateKeyEntry(
            final String alias,
            final Key privateKey,
            final String password,
            final X509Certificate... certificateChain) {
        this.alias = alias;
        this.privateKey = privateKey;
        this.password = password;
        this.certificateChain = certificateChain.clone();
    }
}
