package spiffe.helper;

import lombok.Builder;
import lombok.Value;

import java.security.cert.X509Certificate;

@Value
class BundleEntry {
    String alias;
    X509Certificate certificate;

    @Builder
    BundleEntry(
            final String alias,
            final X509Certificate certificate) {
        this.alias = alias;
        this.certificate = certificate;
    }

    @Override
    public String toString() {
        return "BundleEntry{" +
                "alias='" + alias + '\'' +
                '}';
    }
}
