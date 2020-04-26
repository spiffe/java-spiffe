package spiffe.helper;

import lombok.Builder;
import lombok.Value;

import java.security.Key;
import java.security.cert.X509Certificate;

@Value
class PrivateKeyEntry {
    String alias;
    Key privateKey;
    char[] password;
    X509Certificate[] certificateChain;

    @Builder
    PrivateKeyEntry(
            final String alias,
            final Key privateKey,
            final char[] password,
            final X509Certificate[] certificateChain) {
        this.alias = alias;
        this.privateKey = privateKey;
        this.password = password;
        this.certificateChain = certificateChain;
    }

    @Override
    public String toString() {
        return "PrivateKeyEntry{" +
                "alias='" + alias + '\'' +
                '}';
    }
}
