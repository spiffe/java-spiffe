package io.spiffe.svid.x509svid;

import io.spiffe.exception.X509SvidException;
import io.spiffe.internal.CertificateUtils;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

final class X509SvidProfile {

    private static final int URI_SAN_TYPE = 6;

    private X509SvidProfile() {
    }

    static void validateLeaf(final X509Certificate leaf) throws CertificateException, X509SvidException {
        validateLeafHasSingleUriSan(leaf);
        validateLeafCertificate(leaf);
    }

    static void validateLeafHasSingleUriSan(final X509Certificate leaf)
            throws CertificateException, X509SvidException {
        final Collection<List<?>> subjectAlternativeNames = leaf.getSubjectAlternativeNames();

        int uriSanCount = 0;
        if (subjectAlternativeNames != null) {
            for (List<?> sanEntry : subjectAlternativeNames) {
                if (sanEntry == null || sanEntry.isEmpty()) {
                    continue;
                }

                Object sanType = sanEntry.get(0);
                if (sanType instanceof Integer && (Integer) sanType == URI_SAN_TYPE) {
                    uriSanCount++;
                }
            }
        }

        if (uriSanCount != 1) {
            throw new X509SvidException("Leaf certificate must contain exactly one URI SAN");
        }
    }

    static void validateLeafCertificate(final X509Certificate leaf) throws X509SvidException {
        if (CertificateUtils.isCA(leaf)) {
            throw new X509SvidException("Leaf certificate must not have CA flag set to true");
        }
        validateKeyUsageOfLeafCertificate(leaf);
    }

    private static void validateKeyUsageOfLeafCertificate(final X509Certificate leaf) throws X509SvidException {
        if (!CertificateUtils.hasKeyUsageDigitalSignature(leaf)) {
            throw new X509SvidException("Leaf certificate must have 'digitalSignature' as key usage");
        }
        if (CertificateUtils.hasKeyUsageCertSign(leaf)) {
            throw new X509SvidException("Leaf certificate must not have 'keyCertSign' as key usage");
        }
        if (CertificateUtils.hasKeyUsageCRLSign(leaf)) {
            throw new X509SvidException("Leaf certificate must not have 'cRLSign' as key usage");
        }
    }
}
