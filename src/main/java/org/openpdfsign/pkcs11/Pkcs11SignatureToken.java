package org.openpdfsign.pkcs11;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import org.openpdfsign.SessionInitiator;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of SignatureTokenConnection for PKCS#11 tokens.
 * This class directly uses IAIK PKCS#11 Wrapper to interact with HSM.
 */
import org.openpdfsign.SignatureParameters; // Added import

public class Pkcs11SignatureToken implements SignatureTokenConnection {

    private static final Logger log = Logger.getLogger(Pkcs11SignatureToken.class);

    private String pkcs11LibraryPath;
    private KeyStore.PasswordProtection passwordProtection;
    private int slotIndex;
    private SignatureParameters signatureParams; // Added field for SignatureParameters
    private Module pkcs11Module;
    private Session session;
    private List<DSSPrivateKeyEntry> keys = new ArrayList<>();

    /**
     * Constructor for Pkcs11SignatureToken.
     * 
     * @param pkcs11LibraryPath The path to the PKCS#11 library
     * @param passwordProtection The password protection for the token
     * @param slotIndex The slot index to use
     * @param params The signature parameters, used for certificate label lookup
     */
    public Pkcs11SignatureToken(String pkcs11LibraryPath, KeyStore.PasswordProtection passwordProtection, int slotIndex, SignatureParameters params) { // Added SignatureParameters
        this.pkcs11LibraryPath = pkcs11LibraryPath;
        this.passwordProtection = passwordProtection;
        this.slotIndex = slotIndex;
        this.signatureParams = params; // Store SignatureParameters

        try {
            // Initialize the PKCS#11 module
            pkcs11Module = Module.getInstance(pkcs11LibraryPath);
            pkcs11Module.initialize(null);

            // Initialize the session
            char[] pin = passwordProtection.getPassword();
            session = SessionInitiator.defaultSessionInitiator().initiateSession(pkcs11Module, pin, slotIndex);

            if (session == null) {
                throw new IOException("Failed to initialize PKCS#11 session");
            }

            // Load all private keys
            PrivateKey keyTemplate = new PrivateKey();
            log.debug("Searching for private keys in HSM");
            session.findObjectsInit(keyTemplate);
            Object[] foundKeys = session.findObjects(100); // Find up to 100 keys
            session.findObjectsFinal();

            log.debug("Found " + foundKeys.length + " private keys in HSM");

            if (foundKeys.length == 0) {
                throw new IOException("No private keys found in the HSM");
            }

            // For each private key, find the corresponding certificate and create a DSSPrivateKeyEntry
            for (Object obj : foundKeys) {
                PrivateKey privateKey = (PrivateKey) obj;
                X509PublicKeyCertificate pkcs11Cert = null;
                Object[] foundCerts = null;

                String hsmCertLabelParam = (this.signatureParams != null) ? this.signatureParams.getHsmCertLabel() : null;

                if (hsmCertLabelParam != null && !hsmCertLabelParam.isEmpty()) {
                    log.debug("Attempting to find certificate using --hsm-cert-label: '" + hsmCertLabelParam + "'");
                    X509PublicKeyCertificate certTemplateByParam = new X509PublicKeyCertificate();
                    certTemplateByParam.getLabel().setCharArrayValue(hsmCertLabelParam.toCharArray());
                    session.findObjectsInit(certTemplateByParam);
                    foundCerts = session.findObjects(1);
                    session.findObjectsFinal();
                    if (foundCerts.length > 0) {
                        pkcs11Cert = (X509PublicKeyCertificate) foundCerts[0];
                        log.debug("Found certificate using --hsm-cert-label: '" + hsmCertLabelParam + "'");
                    } else {
                        log.debug("No certificate found using --hsm-cert-label: '" + hsmCertLabelParam + "'");
                    }
                }

                // If pkcs11Cert is still null (i.e., not found by hsmCertLabelParam if it was provided),
                // AND hsmCertLabelParam was not provided (null or empty), then try the default label "X509 Certificate".
                if (pkcs11Cert == null && (hsmCertLabelParam == null || hsmCertLabelParam.isEmpty())) {
                    log.debug("Certificate not found by a specific --hsm-cert-label (or no label was provided). Trying with default label 'X509 Certificate'.");
                    String defaultCertLabel = "X509 Certificate";
                    X509PublicKeyCertificate certTemplateDefault = new X509PublicKeyCertificate();
                    certTemplateDefault.getLabel().setCharArrayValue(defaultCertLabel.toCharArray());
                    session.findObjectsInit(certTemplateDefault);
                    foundCerts = session.findObjects(1); // Reusing foundCerts declared in the loop
                    session.findObjectsFinal();
                    if (foundCerts.length > 0) {
                        pkcs11Cert = (X509PublicKeyCertificate) foundCerts[0];
                        log.debug("Found certificate with default label: '" + defaultCertLabel + "'");
                    } else {
                        log.debug("No certificate found with default label: '" + defaultCertLabel + "'");
                    }
                }

                // After all applicable attempts, if no certificate is found for the current private key, throw an error.
                if (pkcs11Cert == null) {
                    String errorMessage;
                    char[] currentKeyLabelChars = privateKey.getLabel().getCharArrayValue();
                    String currentKeyLabel = "[unlabeled private key]";
                    if (currentKeyLabelChars != null && currentKeyLabelChars.length > 0) {
                        currentKeyLabel = "'" + new String(currentKeyLabelChars) + "'";
                    }

                    if (hsmCertLabelParam != null && !hsmCertLabelParam.isEmpty()) {
                        // This means hsmCertLabelParam was provided, and lookup for that label failed.
                        // The default label "X509 Certificate" was not attempted by the logic above in this specific case.
                        errorMessage = "No X509 certificate found in HSM for private key " + currentKeyLabel +
                                       " using the specified --hsm-cert-label: '" + hsmCertLabelParam + "'.";
                    } else {
                        // This means hsmCertLabelParam was NOT provided (or was empty).
                        // The default label "X509 Certificate" was attempted and failed.
                        errorMessage = "No X509 certificate found in HSM for private key " + currentKeyLabel +
                                       " using the default label 'X509 Certificate' (as --hsm-cert-label was not provided or was empty).";
                    }
                    log.error(errorMessage);
                    throw new IOException(errorMessage); // This will be caught by the existing catch block in the constructor
                }

                if (pkcs11Cert != null) {
                    // Convert PKCS#11 certificate to Java X509Certificate
                    X509Certificate[] certChain = convertToX509CertificateChain(pkcs11Cert);
                    // Create a DSSPrivateKeyEntry
                    IAIKPrivateKeyEntry entry = new IAIKPrivateKeyEntry(privateKey, pkcs11Cert, certChain);
                    keys.add(entry);
                    log.debug("Added key with alias: '" + entry.getAlias() + "' associated with certificate subject: '" + certChain[0].getSubjectX500Principal().getName() + "'");
                } else {
                    // This case is now handled by the log.warn above if no cert is found at all.
                }
            }
        } catch (TokenException | IOException | CertificateException e) {
            throw new RuntimeException("Failed to initialize PKCS#11 module or load keys: " + e.getMessage(), e);
        }
    }

    /**
     * Converts a PKCS#11 certificate to a Java X509Certificate chain.
     * 
     * @param pkcs11Cert The PKCS#11 certificate
     * @return The Java X509Certificate chain
     * @throws CertificateException If there is an error converting the certificate
     */
    private X509Certificate[] convertToX509CertificateChain(X509PublicKeyCertificate pkcs11Cert) throws CertificateException {
        byte[] certValue = pkcs11Cert.getValue().getByteArrayValue();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certValue));
        return new X509Certificate[] { cert };
    }

    @Override
    public List<DSSPrivateKeyEntry> getKeys() {
        return keys;
    }

    @Override
    public DSSPrivateKeyEntry getKey(String alias) {
        for (DSSPrivateKeyEntry key : keys) {
            if (alias.equals(key.getAlias())) {
                return key;
            }
        }
        return null;
    }

    @Override
    public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, DSSPrivateKeyEntry privateKey) {
            try {
                IAIKPrivateKeyEntry iaikKey = (IAIKPrivateKeyEntry) privateKey;
                PrivateKey pkcs11Key = iaikKey.getPrivateKey();
                iaik.pkcs.pkcs11.Mechanism signatureMechanism;
                String keyAlgo = iaikKey.getEncryptionAlgorithm().toUpperCase();
    
                byte[] dataToSignActual = toBeSigned.getBytes(); // Get original bytes from ToBeSigned
    
                if (keyAlgo.contains("EC") || keyAlgo.contains("ECDSA")) {
                    String javaDigestAlgoName;
                    int expectedDigestLengthBytes;
    
                    switch (digestAlgorithm) {
                        case SHA1:
                            javaDigestAlgoName = "SHA-1";
                            expectedDigestLengthBytes = 20;
                            break;
                        case SHA256:
                            javaDigestAlgoName = "SHA-256";
                            expectedDigestLengthBytes = 32;
                            break;
                        case SHA384:
                            javaDigestAlgoName = "SHA-384";
                            expectedDigestLengthBytes = 48;
                            break;
                        case SHA512:
                            javaDigestAlgoName = "SHA-512";
                            expectedDigestLengthBytes = 64;
                            break;
                        default:
                            log.error("Unsupported digest algorithm for ECDSA: " + digestAlgorithm.getName());
                            throw new RuntimeException("Unsupported digest algorithm for ECDSA: " + digestAlgorithm.getName());
                    }
    
                    log.debug("ECDSA: Original data length: " + dataToSignActual.length + ", Expected digest length for " + javaDigestAlgoName + ": " + expectedDigestLengthBytes);
    
                    // CKM_ECDSA expects the hash of the data, not the data itself.
                    // If the input data is not already a hash of the correct length, hash it.
                    if (dataToSignActual.length != expectedDigestLengthBytes) {
                        log.debug("Data is not a pre-computed hash or has unexpected length. Digesting with " + javaDigestAlgoName);
                        try {
                            java.security.MessageDigest md = java.security.MessageDigest.getInstance(javaDigestAlgoName);
                            dataToSignActual = md.digest(dataToSignActual); // Use the determined digest algorithm
                            log.debug("Digested data length for signing: " + dataToSignActual.length);
                        } catch (java.security.NoSuchAlgorithmException e) {
                            log.error("Failed to create digest instance for " + javaDigestAlgoName + ": " + e.getMessage(), e);
                            throw new RuntimeException("Failed to create digest for ECDSA: " + e.getMessage(), e);
                        }
                    } else {
                        log.debug("Data appears to be a pre-computed hash. Using as is for ECDSA.");
                    }
                    signatureMechanism = iaik.pkcs.pkcs11.Mechanism.get(iaik.pkcs.pkcs11.wrapper.PKCS11Constants.CKM_ECDSA);
                    log.debug("Using ECDSA mechanism: CKM_ECDSA with " + digestAlgorithm.getName() + " digest implicitly handled or pre-hashed.");
                } else if (keyAlgo.contains("RSA")) {
                    // For RSA, mechanisms like CKM_SHA256_RSA_PKCS handle hashing internally.
                    // dataToSignActual (original bytes from toBeSigned) is used directly.
                    if (digestAlgorithm == DigestAlgorithm.SHA1) {
                        signatureMechanism = iaik.pkcs.pkcs11.Mechanism.get(iaik.pkcs.pkcs11.wrapper.PKCS11Constants.CKM_SHA1_RSA_PKCS);
                        log.debug("Using RSA mechanism: CKM_SHA1_RSA_PKCS");
                    } else if (digestAlgorithm == DigestAlgorithm.SHA256) {
                        signatureMechanism = iaik.pkcs.pkcs11.Mechanism.get(iaik.pkcs.pkcs11.wrapper.PKCS11Constants.CKM_SHA256_RSA_PKCS);
                        log.debug("Using RSA mechanism: CKM_SHA256_RSA_PKCS");
                    } else if (digestAlgorithm == DigestAlgorithm.SHA384) {
                        signatureMechanism = iaik.pkcs.pkcs11.Mechanism.get(iaik.pkcs.pkcs11.wrapper.PKCS11Constants.CKM_SHA384_RSA_PKCS);
                        log.debug("Using RSA mechanism: CKM_SHA384_RSA_PKCS");
                    } else if (digestAlgorithm == DigestAlgorithm.SHA512) {
                        signatureMechanism = iaik.pkcs.pkcs11.Mechanism.get(iaik.pkcs.pkcs11.wrapper.PKCS11Constants.CKM_SHA512_RSA_PKCS);
                        log.debug("Using RSA mechanism: CKM_SHA512_RSA_PKCS");
                    } else {
                        signatureMechanism = iaik.pkcs.pkcs11.Mechanism.get(iaik.pkcs.pkcs11.wrapper.PKCS11Constants.CKM_RSA_PKCS);
                        log.warn("Using generic RSA_PKCS mechanism due to unhandled digest algorithm: " + digestAlgorithm.getName() + ". Hashing must be ensured by data or HSM.");
                    }
                } else {
                    log.error("Unsupported key algorithm for PKCS#11 signing: " + keyAlgo);
                    throw new RuntimeException("Unsupported key algorithm for PKCS#11 signing: " + keyAlgo);
                }
    
                session.signInit(signatureMechanism, pkcs11Key);
                byte[] signatureBytes = session.sign(dataToSignActual); // Sign the (potentially hashed) data
    
                return new SignatureValue(digestAlgorithm, signatureBytes);
            } catch (TokenException e) {
    // ...existing code...
            throw new RuntimeException("Failed to sign data: " + e.getMessage(), e);
        }
    }

    @Override
    public void close() throws Exception {
        if (session != null) {
            try {
                session.closeSession();
            } catch (TokenException e) {
                throw new Exception("Failed to close PKCS#11 session: " + e.getMessage(), e);
            }
        }

        if (pkcs11Module != null) {
            try {
                pkcs11Module.finalize(null);
            } catch (TokenException e) {
                throw new Exception("Failed to finalize PKCS#11 module: " + e.getMessage(), e);
            }
        }
    }

    // Using the existing IAIKPrivateKeyEntry class instead of defining a nested class
}
