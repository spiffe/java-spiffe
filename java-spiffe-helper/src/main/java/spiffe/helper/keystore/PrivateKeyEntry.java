package spiffe.helper.keystore;

import lombok.Builder;
import lombok.Value;

import java.security.Key;
import java.security.cert.X509Certificate;

@Value
class PrivateKeyEntry {
    String alias;
    Key privateKey;
    String password;
    X509Certificate[] certificateChain;

    @Builder
    PrivateKeyEntry(
            final String alias,
            final Key privateKey,
            final String password,
            final X509Certificate[] certificateChain) {
        this.alias = alias;
        this.privateKey = privateKey;
        this.password = password;
        this.certificateChain = certificateChain;
    }
}
