package io.spiffe.helper.keystore;

import java.security.Key;
import java.security.cert.X509Certificate;

import java.util.Arrays;
import java.util.Objects;

class PrivateKeyEntry {

    private final String alias;
    private final Key privateKey;
    private final String password;
    private final X509Certificate[] certificateChain;

    PrivateKeyEntry(
            final String alias,
            final Key privateKey,
            final String password,
            final X509Certificate... certificateChain) {
        this.alias = alias;
        this.privateKey = privateKey;
        this.password = password;
        this.certificateChain = certificateChain != null ? certificateChain.clone() : null;
    }

    public String getAlias() {
        return alias;
    }

    public Key getPrivateKey() {
        return privateKey;
    }

    public String getPassword() {
        return password;
    }

    public X509Certificate[] getCertificateChain() {
        return certificateChain != null ? certificateChain.clone() : null;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String alias;
        private Key privateKey;
        private String password;
        private X509Certificate[] certificateChain;

        public Builder alias(String alias) {
            this.alias = alias;
            return this;
        }

        public Builder privateKey(Key privateKey) {
            this.privateKey = privateKey;
            return this;
        }

        public Builder password(String password) {
            this.password = password;
            return this;
        }

        public Builder certificateChain(X509Certificate... certificateChain) {
            this.certificateChain = certificateChain;
            return this;
        }

        public PrivateKeyEntry build() {
            return new PrivateKeyEntry(alias, privateKey, password, certificateChain);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PrivateKeyEntry)) return false;
        PrivateKeyEntry that = (PrivateKeyEntry) o;
        return Objects.equals(alias, that.alias)
                && Objects.equals(privateKey, that.privateKey)
                && Objects.equals(password, that.password)
                && Arrays.equals(certificateChain, that.certificateChain);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(alias, privateKey, password);
        result = 31 * result + Arrays.hashCode(certificateChain);
        return result;
    }

    @Override
    public String toString() {
        return "PrivateKeyEntry(" +
                "alias='" + alias + '\'' +
                ", privateKey=" + privateKey +
                ", password='[PROTECTED]'" +
                ", certificateChain=" + Arrays.toString(certificateChain) +
                ')';
    }
}
