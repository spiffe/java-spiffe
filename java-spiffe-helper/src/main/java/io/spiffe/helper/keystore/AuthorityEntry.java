package io.spiffe.helper.keystore;

import java.security.cert.X509Certificate;

class AuthorityEntry {
    String alias;
    X509Certificate certificate;

    AuthorityEntry(
            final String alias,
            final X509Certificate certificate) {
        this.alias = alias;
        this.certificate = certificate;
    }

    public String getAlias() {
        return alias;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public static class Builder {
        private String alias;
        private X509Certificate certificate;

        public Builder alias(String alias) {
            this.alias = alias;
            return this;
        }

        public Builder certificate(X509Certificate certificate) {
            this.certificate = certificate;
            return this;
        }

        public AuthorityEntry build() {
            return new AuthorityEntry(alias, certificate);
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
