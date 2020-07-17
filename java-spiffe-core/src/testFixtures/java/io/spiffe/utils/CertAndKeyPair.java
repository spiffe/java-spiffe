package io.spiffe.utils;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public class CertAndKeyPair {
    KeyPair keyPair;
    X509Certificate certificate;

    public CertAndKeyPair(X509Certificate certificate, KeyPair keyPair) {
        this.keyPair = keyPair;
        this.certificate = certificate;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }
}
