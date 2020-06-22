package io.spiffe.utils;

import lombok.Value;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class X509CertificateTestUtils {

    /**
     * Creates a self-signed Root CA certificate
     */
    public static CertAndKeyPair createRootCA(String subject, String spiffeId) throws Exception {
        KeyPair certKeyPair = generateKeyPair();
        JcaX509v3CertificateBuilder builder = getCertificateBuilder(certKeyPair, subject, subject);
        addCAExtensions(builder, certKeyPair, spiffeId);

        // self signed
        X509Certificate cert = getSignedX509Certificate(certKeyPair.getPrivate(), builder);
        return new CertAndKeyPair(cert, certKeyPair);
    }

    /**
     * Creates a certificate signed with the private key of the issuer. The generated cert can be an intermediate CA or
     * a leaf certificate.
     */
    public static CertAndKeyPair createCertificate(String subject, String issuerSubject, String spiffeId, CertAndKeyPair issuer, boolean isCa) throws Exception {
        KeyPair certKeyPair = generateKeyPair();
        PrivateKey issuerKey = issuer.keyPair.getPrivate();
        JcaX509v3CertificateBuilder builder = getCertificateBuilder(certKeyPair, subject, issuerSubject);
        addCertExtensions(builder, spiffeId, isCa);
        X509Certificate cert = getSignedX509Certificate(issuerKey, builder);
        return new CertAndKeyPair(cert, certKeyPair);
    }

    @Value
    public final static class CertAndKeyPair {
        private final KeyPair keyPair;
        private final X509Certificate certificate;

        public CertAndKeyPair(X509Certificate certificate, KeyPair keyPair) {
            this.keyPair = keyPair;
            this.certificate = certificate;
        }
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        return keyGen.generateKeyPair();
    }

    private static void addCertExtensions(JcaX509v3CertificateBuilder builder, String spiffeId, boolean isCa) throws CertIOException {
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));

        if (isCa) {
            KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.cRLSign);
            builder.addExtension(Extension.keyUsage, true, usage);
        } else {
            KeyUsage usage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement);
            builder.addExtension(Extension.keyUsage, true, usage);

            ASN1EncodableVector purposes = new ASN1EncodableVector();
            purposes.add(KeyPurposeId.id_kp_serverAuth);
            purposes.add(KeyPurposeId.id_kp_clientAuth);
            builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));
        }

        if (StringUtils.isNotBlank(spiffeId)) {
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, spiffeId )));
        }
    }

    private static void addCAExtensions(JcaX509v3CertificateBuilder builder, KeyPair certKeyPair, String spiffeId) throws CertIOException {
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.cRLSign);
        builder.addExtension(Extension.keyUsage, true, usage);

        builder.addExtension(Extension.subjectAlternativeName, true,
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, spiffeId)));

        builder.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(certKeyPair.getPublic().getEncoded()));
    }

    private static JcaX509v3CertificateBuilder getCertificateBuilder(KeyPair certKeyPair, String subject, String issuerSubject) {
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Instant validFrom = Instant.now().minus(5, ChronoUnit.DAYS);
        Instant validUntil = validFrom.plus(30 , ChronoUnit.DAYS);
        X500Name name = new X500Name(subject);
        X500Name issuerName = new X500Name(issuerSubject);
        return new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                Date.from(validFrom), Date.from(validUntil),
                name, certKeyPair.getPublic());
    }

    private static X509Certificate getSignedX509Certificate(PrivateKey issuerKey, JcaX509v3CertificateBuilder builder) throws OperatorCreationException, CertificateException {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(issuerKey);
        X509CertificateHolder certHolder = builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }
}


