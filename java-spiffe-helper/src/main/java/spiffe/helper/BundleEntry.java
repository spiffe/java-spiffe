package spiffe.helper;

import lombok.Builder;
import lombok.Value;

import java.security.cert.Certificate;

@Value
class BundleEntry {
    String alias;
    Certificate certificate;

    @Builder
    BundleEntry(
            final String alias,
            final Certificate certificate) {
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
