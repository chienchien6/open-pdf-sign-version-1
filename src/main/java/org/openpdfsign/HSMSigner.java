package org.openpdfsign;

import com.beust.jcommander.Strings;
// Using IAIKPKCS11Wrapper equivalents as per requirements
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.tsp.CompositeTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.apache.commons.io.IOUtils;
import iaik.pkcs.pkcs11.Mechanism; // For DigestAlgorithm
import iaik.pkcs.pkcs11.objects.Data; // For ToBeSigned
// Using local implementations instead of eu.europa.esig.dss classes
import org.apache.commons.lang3.StringUtils;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.PDDocument; // Added for page count
import org.openpdfsign.dss.PdfBoxNativeTableObjectFactory;
import org.openpdfsign.pkcs11.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;


/**
 * Extension of the Signer class that adds support for HSM (Hardware Security Module) signing
 * using PKCS#11 interface.
 *
 * This implementation uses a PKCS#11 token for signing operations, but creates a JKS token wrapper
 * to make it compatible with the parent Signer class which expects a JKSSignatureToken.
 * The JKS token wrapper delegates the actual signing operation to the PKCS#11 token.
 */
public class HSMSigner extends Signer {
    private static final float POINTS_PER_INCH = 72;
    private static final float POINTS_PER_MM = 1 / (10 * 2.54f) * POINTS_PER_INCH;

    private static final Logger log = Logger.getLogger(HSMSigner.class);

    /**
     * Signs a PDF document using either a JKS keystore or an HSM via PKCS#11.
     *
     * @param pdfFile The PDF file to sign
     * @param outputFile The output file where the signed PDF will be saved
     * @param keyStore The keystore bytes (used only if HSM is not used)
     * @param keyStorePassword The keystore password (used only if HSM is not used)
     * @param binaryOutput The output stream for binary output (optional)
     * @param params The signature parameters
     * @throws IOException If there is an error reading or writing files
     */
    @Override
    public void signPdf(Path pdfFile, Path outputFile, byte[] keyStore,
                        char[] keyStorePassword, OutputStream binaryOutput,
                        SignatureParameters params) throws IOException {
        if (!Strings.isStringEmpty(params.getHsmLibrary())) {
            signPdfWithHsm(pdfFile, outputFile, binaryOutput, params);
        } else {
            super.signPdf(pdfFile, outputFile, keyStore, keyStorePassword,
                    binaryOutput, params);
        }
    }



    private void signPdfWithHsm(Path pdfFile, Path outputFile,
                                OutputStream binaryOutput,
                                SignatureParameters params) throws IOException {
        SignatureTokenConnection token = null;
        try {
            // 创建PKCS11令牌
            token = new Pkcs11SignatureToken(
                    params.getHsmLibrary(),
                    new KeyStore.PasswordProtection(params.getHsmPin().toCharArray()),
                    params.getHsmSlot(),
                    params // Pass SignatureParameters
            );

            // 获取密钥
            List<DSSPrivateKeyEntry> keys = token.getKeys();
            if (keys.isEmpty()) {
                throw new IOException("No keys found in HSM");
            }

            // 选择签名密钥
            DSSPrivateKeyEntry signingKey = selectSigningKey(keys, params);
            // 打印密鑰算法和證書信息 is now part of selectSigningKey logging or done after this call as before
log.debug("Key Algorithm: " + signingKey.getEncryptionAlgorithm());
log.debug("Certificate SN: " + signingKey.getCertificate().getSerialNumber());
            // 直接使用token进行签名
            signPdfWithToken(pdfFile, outputFile, binaryOutput, params, token, signingKey);

        } finally {
            if (token != null) {
                try {
                    token.close();
                } catch (Exception e) {
                    log.error("Error closing HSM token", e);
                }
            }
        }
    }

    /**
 * Creates a CommonCertificateVerifier based on the signature parameters.
 * @param signatureParameters The PAdES signature parameters.
 * @return Configured CommonCertificateVerifier instance.
 */
private CommonCertificateVerifier createCertificateVerifier(PAdESSignatureParameters signatureParameters) {
    CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

    // Check signature level using reflection
    SignatureLevel level = null;
    try {
        level = (SignatureLevel) signatureParameters.getClass().getMethod("getSignatureLevel").invoke(signatureParameters);
    } catch (Exception e) {
        log.error("Error getting signature level: " + e.getMessage(), e);
        // Default to LT level to ensure we set up the verifier properly
        level = SignatureLevel.PAdES_BASELINE_LT;
    }

    if (level == SignatureLevel.PAdES_BASELINE_LT ||
            level == SignatureLevel.PAdES_BASELINE_LTA) {
        // Capability to download resources from AIA
        commonCertificateVerifier.setAIASource(new DefaultAIASource());

        // Capability to request OCSP Responders
        commonCertificateVerifier.setOcspSource(new OnlineOCSPSource());

        // Capability to download CRL
        commonCertificateVerifier.setCrlSource(new OnlineCRLSource());

        // Still fetch revocation data for signing, even if a certificate chain is not trusted
        commonCertificateVerifier.setCheckRevocationForUntrustedChains(true);

        // Create an instance of a trusted certificate source
        CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();

        // Import defaults or custom certificates if needed
        CommonCertificateSource commonCertificateSource = new CommonCertificateSource();
        trustedCertSource.importAsTrusted(commonCertificateSource);

        commonCertificateVerifier.addTrustedCertSources(trustedCertSource);
    }
    return commonCertificateVerifier;
}

private DSSPrivateKeyEntry selectSigningKey(List<DSSPrivateKeyEntry> keys,
                                            SignatureParameters params) throws IOException {
    String pkeyLabel = params.getHsmPkeyLabel();
    String certLabel = params.getHsmCertLabel();

    // Ensure there are keys to select from
    if (keys.isEmpty()) {
        throw new IOException("No keys found in HSM. Cannot select a signing key.");
    }

    Stream<DSSPrivateKeyEntry> stream = keys.stream();
    String usedCriteria = "none (defaulting to first key)";
    boolean criteriaProvided = false;

    // Log available key aliases/labels for debugging

        String availableAliases = keys.stream()
                                    .map(DSSPrivateKeyEntry::getAlias)
                                    .filter(Objects::nonNull)
                                    .distinct()
                                    .collect(Collectors.joining(", "));
        log.debug("Available key aliases/labels in HSM: [" + availableAliases + "]");

    
    // hsmPkeyLabel is now mandatory for key selection.
    if (Strings.isStringEmpty(pkeyLabel)) {
        log.error("HSM private key label (--hsm-pkey-label) not specified. This parameter is now mandatory.");
        throw new IOException("HSM private key label (--hsm-pkey-label) not specified. This parameter is now mandatory.");
    }

    // At this point, pkeyLabel is guaranteed to be non-empty.
    log.debug("Attempting to select key using hsmPkeyLabel: '" + pkeyLabel + "'");
    // This assumes key.getAlias() corresponds to the CKA_LABEL of the CKO_PRIVATE_KEY object.
    // Class CKO_PRIVATE_KEY and Type (e.g., CKK_ECDSA) are implicitly handled by Pkcs11SignatureToken.
    stream = stream.filter(key -> pkeyLabel.equals(key.getAlias()));
    usedCriteria = "hsmPkeyLabel='" + pkeyLabel + "'";
    criteriaProvided = true; // pkeyLabel is the only criterion now, and it was provided.

    // Collect the filtered keys. This list will be used by the subsequent code.
    List<DSSPrivateKeyEntry> filteredKeys = stream.collect(Collectors.toList());

    if (filteredKeys.isEmpty()) {
        // This block is reached if pkeyLabel was provided, but no key matched it.
        // criteriaProvided is implicitly true here.
        String availableAliasesForError = keys.stream()
                                            .map(DSSPrivateKeyEntry::getAlias)
                                            .filter(Objects::nonNull)
                                            .distinct()
                                            .collect(Collectors.joining("', '"));
        throw new IOException("Key with specified hsmPkeyLabel '" + pkeyLabel + "' not found in HSM. " +
                              "Available aliases/labels: ['" + availableAliasesForError + "']. " +
                              "Ensure the label matches exactly and the private key object exists with that label.");
    }
    // If filteredKeys is not empty, the code following this replaced block will handle it
    // (e.g., warning for multiple matches, selecting the first one).
    // The `return keys.get(0);` from the original `else` branch (no criteria) is correctly removed,
    // as lack of pkeyLabel is now an error handled above.

    if (filteredKeys.size() > 1 && criteriaProvided) {
        String matchingAliases = filteredKeys.stream()
                                        .map(DSSPrivateKeyEntry::getAlias)
                                        .filter(Objects::nonNull)
                                        .distinct()
                                        .collect(Collectors.joining("', '"));
        log.warn("Multiple keys (" + filteredKeys.size() + ") found matching criteria (" + usedCriteria + "): ['" + matchingAliases + "']. " +
                 "Using the first one found: '" + (filteredKeys.get(0).getAlias() != null ? filteredKeys.get(0).getAlias() : "NO_ALIAS") + "'. " +
                 "Consider using a more specific label if this is not the intended key.");
    }
    
    DSSPrivateKeyEntry selectedKey = filteredKeys.get(0);

        log.debug("Selected key with alias/label: '" + (selectedKey.getAlias() != null ? selectedKey.getAlias() : "NO_ALIAS") + "' using criteria: " + usedCriteria);
        log.debug("Selected key's PKCS#11 object class is implicitly CKO_PRIVATE_KEY.");
        log.debug("Selected key's PKCS#11 object type (e.g. CKK_ECDSA, CKK_RSA) reflected in algorithm: " + selectedKey.getEncryptionAlgorithm());
        if (selectedKey.getCertificate() != null) {
            log.debug("Associated certificate's PKCS#11 object class is implicitly CKO_CERTIFICATE, type CKC_X_509.");
            log.debug("Selected key's certificate SN: " + selectedKey.getCertificate().getSerialNumber());
            log.debug("Selected key's certificate SubjectDN: " + selectedKey.getCertificate().getSubjectX500Principal().getName());
        } else {
            log.warn("Selected key does not have an associated certificate in DSSPrivateKeyEntry.");
        }

    return selectedKey;
}
    /**
     * Signs a PDF document using the provided token and key.
     * This method uses the parent class's signPdf method with the custom token.
     *
     * @param pdfFile The PDF file to sign
     * @param outputFile The output file where the signed PDF will be saved
     * @param binaryOutput The output stream for binary output (optional)
     * @param params The signature parameters
     * @param token The token to use for signing
     * @param signingKey The key to use for signing
     * @throws IOException If there is an error reading or writing files
     */

    protected void signPdfWithToken(Path pdfFile, Path outputFile,
                                    OutputStream binaryOutput,
                                    SignatureParameters params,
                                    SignatureTokenConnection token,
                                    DSSPrivateKeyEntry signingKey) throws IOException {
        try {
            DSSDocument toSignDocument = new FileDocument(pdfFile.toFile());

            // 创建签名参数
            PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();

            // Convert X509Certificate to CertificateToken and set it
            X509Certificate cert = signingKey.getCertificate();
            CertificateToken certToken = new CertificateToken(cert);
            signatureParameters.setSigningCertificate(certToken);

            // Convert X509Certificate[] to List<CertificateToken> and set it
            X509Certificate[] certChain = signingKey.getCertificateChain();
            List<CertificateToken> certTokenChain = new ArrayList<>();
            for (X509Certificate chainCert : certChain) {
                certTokenChain.add(new CertificateToken(chainCert));
            }
            signatureParameters.setCertificateChain(certTokenChain);

            // 配置签名参数
            configureSignatureParameters(signatureParameters, params);

            // 设置代理（如果需要）
            ProxyConfig proxyConfig = this.retrieveProxyConfig();

            // 创建验证器
            CommonCertificateVerifier commonCertificateVerifier = createCertificateVerifier(signatureParameters);

            // 创建签名服务
            PAdESService service = new PAdESService(commonCertificateVerifier);

            // 配置可视签名（如果需要）
            if (params.getPage() != null) {
                SignatureImageParameters imageParameters = new SignatureImageParameters();
                TableSignatureFieldParameters fieldParameters = new TableSignatureFieldParameters();
                imageParameters.setFieldParameters(fieldParameters);

                try {
                    if (!Strings.isStringEmpty(params.getImageFile())) {
                        imageParameters.setImage(new InMemoryDocument(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(params.getImageFile()))));
                    } else {
                        imageParameters.setImage(new InMemoryDocument(IOUtils.toByteArray(getClass().getClassLoader().getResourceAsStream("signature.png"))));
                    }

                    // Add new page if user requested, force reopen document
                    if (params.getAddPage() != null && params.getAddPage() == true) {
                        PDDocument pdDocument = PDDocument.load(toSignDocument.openStream());
                        PDPage newPage = new PDPage(pdDocument.getPage(pdDocument.getNumberOfPages() - 1).getMediaBox());
                        pdDocument.addPage(newPage);
                        Set<COSDictionary> cosSet = new HashSet<>();
                        cosSet.add(newPage.getCOSObject().getCOSDictionary(COSName.PARENT));
                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        pdDocument.saveIncremental(bos, cosSet);
                        pdDocument.close();
                        toSignDocument = new InMemoryDocument(bos.toByteArray());
                    }

                    if (params.getPage() < 0) {
                        PDDocument pdDocument = PDDocument.load(toSignDocument.openStream());
                        int pageCount = pdDocument.getNumberOfPages();
                        fieldParameters.setPage(pageCount + (1 + params.getPage()));
                        pdDocument.close();
                        log.debug("PDF page count: " + pageCount);
                    } else {
                        fieldParameters.setPage(params.getPage());
                    }
                    // Calculate coordinates
                    PDDocument pdDocForCoords = PDDocument.load(toSignDocument.openStream());
                    PDPage pageForCoords;
                    int pageIndexToUse;
                    if (params.getPage() < 0) {
                        pageIndexToUse = pdDocForCoords.getNumberOfPages() + params.getPage();
                    } else {
                        // params.getPage() is 1-indexed from user, convert to 0-indexed for PDFBox
                        pageIndexToUse = params.getPage() -1;
                        if (pageIndexToUse < 0) pageIndexToUse = 0; // Ensure not negative
                    }
                    pageForCoords = pdDocForCoords.getPage(pageIndexToUse);

                    PDRectangle mediaBox = pageForCoords.getMediaBox();
                    int pageRotation = pageForCoords.getRotation();
                    log.debug("Page index for signature: " + pageIndexToUse + ", Rotation: " + pageRotation + " degrees.");

                    // These are dimensions of the *unrotated* page, which is what PDRectangle expects.
                    float pageWidth = mediaBox.getWidth();
                    float pageHeight = mediaBox.getHeight();
                    log.debug(String.format("MediaBox dimensions (unrotated): Width=%.2f pts, Height=%.2f pts", pageWidth, pageHeight));
                    pdDocForCoords.close();

                    float signatureWidthPx = params.getWidth() * POINTS_PER_MM * 10f;
                    float estimatedSignatureHeightPx = signatureWidthPx * 0.6f; // Example: height is 60% of width
                    log.debug(String.format("Signature params: WidthCm=%.2f (%.2f pts), EstimatedHeightPx=%.2f",
                        params.getWidth(), signatureWidthPx, estimatedSignatureHeightPx));

                    // X Coordinate Calculation
                    // Precedence: 1. --right, 2. --left (which defaults to 0cm if not specified)
                    if (params.getRight() != null) {
                        // --right is specified, use it.
                        // OriginX (bottom-left of signature) = pageWidth - (right_offset_in_points) - signature_width_in_points.
                        float xFromRightOffset = params.getRight() * POINTS_PER_MM * 10f;
                        fieldParameters.setOriginX(pageWidth - xFromRightOffset - signatureWidthPx);
                        log.debug(String.format("X ALIGNMENT: Using --right. rightOffsetCm=%.2f, rightOffsetPx=%.2f, pageWidth=%.2f, sigWidthPx=%.2f, OriginX=%.2f",
                                params.getRight(), xFromRightOffset, pageWidth, signatureWidthPx,
                                fieldParameters.getOriginX()));
                    } else {
                        // --right is NOT specified, so use --left (params.getLeft() will return its value or default 0f).
                        // 'left' parameter means distance from the page left edge to the signature field's left edge.
                        // OriginX is the X coordinate of the lower-left corner of the signature field.
                        float xFromLeftOffset = params.getLeft() * POINTS_PER_MM * 10f;
                        fieldParameters.setOriginX(xFromLeftOffset);
                        log.debug(String.format("X ALIGNMENT: Using --left (right not specified). leftOffsetCm=%.2f, leftOffsetPx=%.2f, OriginX=%.2f",
                                params.getLeft(), xFromLeftOffset, fieldParameters.getOriginX()));
                    }

                    // Y Coordinate Calculation
                    // Precedence: 1. --bottom, 2. --top (which defaults to 0cm if not specified)
                    if (params.getBottom() != null) {
                        // --bottom is specified, use it.
                        // PDFBox Y-coordinate starts from the bottom (0 at bottom, increases upwards).
                        // OriginY is the Y coordinate of the lower-left corner of the signature field.
                        float yFromBottomOffset = params.getBottom() * POINTS_PER_MM * 10f;
                        fieldParameters.setOriginY(yFromBottomOffset);
                        log.debug(String.format("Y ALIGNMENT: Using --bottom. bottomOffsetCm=%.2f, bottomOffsetPx=%.2f, OriginY=%.2f",
                                params.getBottom(), yFromBottomOffset, fieldParameters.getOriginY()));
                    } else {
                        // --bottom is NOT specified, so use --top (params.getTop() will return its value or default 0f).
                        // 'top' parameter means distance from the page top to the signature field's top edge.
                        // OriginY (bottom-left of signature) = pageHeight - (top_offset_in_points) - signature_height_in_points.
                        float yFromTopOffset = params.getTop() * POINTS_PER_MM * 10f;
                        fieldParameters.setOriginY(pageHeight - yFromTopOffset - estimatedSignatureHeightPx);
                        log.debug(String.format("Y ALIGNMENT: Using --top (bottom not specified). topOffsetCm=%.2f, topOffsetPx=%.2f, pageHeight=%.2f, estSignHeightPx=%.2f, OriginY=%.2f",
                                params.getTop(), yFromTopOffset, pageHeight, estimatedSignatureHeightPx,
                                fieldParameters.getOriginY()));
                    }

                    fieldParameters.setWidth(params.getWidth() * POINTS_PER_MM * 10f);

                    // Set signature date with timezone consideration
                    DateTimeFormatter formatter = DateTimeFormatter.ISO_OFFSET_DATE_TIME.withZone(ZoneId.systemDefault());
                    if (params.getTimezone() != null) {
                        formatter = formatter.withZone(ZoneId.of(params.getTimezone()));
                    }
                    fieldParameters.setSignatureDate(formatter.format(signatureParameters.getSigningDate().toInstant()));
                    fieldParameters.setSignaturString(signingKey.getCertificate().getSubjectDN().getName());
                    fieldParameters.setLabelHint(org.apache.commons.lang3.ObjectUtils.firstNonNull(params.getLabelHint(), Configuration.getInstance().getResourceBundle().getString("hint")));
                    fieldParameters.setLabelSignee(org.apache.commons.lang3.ObjectUtils.firstNonNull(params.getLabelSignee(), Configuration.getInstance().getResourceBundle().getString("signee")));
                    fieldParameters.setLabelTimestamp(org.apache.commons.lang3.ObjectUtils.firstNonNull(params.getLabelTimestamp(), Configuration.getInstance().getResourceBundle().getString("timestamp")));
                    if (!Strings.isStringEmpty(params.getHint())) {
                        fieldParameters.setHint(params.getHint());
                    } else {
                        if (params.getNoHint()) {
                            fieldParameters.setHint(null);
                        } else {
                            fieldParameters.setHint(Configuration.getInstance().getResourceBundle().getString("hint_text"));
                        }
                    }
                    fieldParameters.setImageOnly(params.getImageOnly());

                    signatureParameters.setImageParameters(imageParameters);

                    PdfBoxNativeObjectFactory pdfBoxNativeObjectFactory = new PdfBoxNativeTableObjectFactory();
                    service.setPdfObjFactory(pdfBoxNativeObjectFactory);
                    log.debug("Visible signature parameters set");
                } catch (Exception e) {
                    log.error("Error configuring visible signature: " + e.getMessage(), e);
                }
            }

            // 配置时间戳（如果需要）
            if (params.getUseTimestamp() || params.getUseLT() || params.getUseLTA() || !params.getTSA().isEmpty()) {
                CompositeTSPSource compositeTSPSource = new CompositeTSPSource();
                Map<String, TSPSource> tspSources = new HashMap<>();
                compositeTSPSource.setTspSources(tspSources);

                if (params.getTSA().isEmpty()) {
                    // Use default TSP sources if none specified
                    tspSources.put("http://timestamp.digicert.com", buildTspSource("http://timestamp.digicert.com", proxyConfig));
                } else {
                    for (String source : params.getTSA()) {
                        tspSources.put(source, buildTspSource(source, proxyConfig));
                    }
                }

                service.setTspSource(compositeTSPSource);
            }

            // 设置PDF密码（如果需要）
            if (!StringUtils.isEmpty(params.getPdfPassphrase())) {
                signatureParameters.setPasswordProtection(params.getPdfPassphrase().toCharArray());
            }

            // 获取要签名的数据
            eu.europa.esig.dss.model.ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);


            // Convert EU DSS ToBeSigned to custom ToBeSigned
            org.openpdfsign.pkcs11.ToBeSigned customToBeSigned = new org.openpdfsign.pkcs11.ToBeSigned(dataToSign.getBytes());
// 檢查數據長度
            log.debug("Data to sign length: " + customToBeSigned.getBytes().length);
            // Convert EU DSS DigestAlgorithm to custom DigestAlgorithm

            // 確認摘要算法

             eu.europa.esig.dss.enumerations.DigestAlgorithm euDigestAlgorithm = signatureParameters.getDigestAlgorithm();
             org.openpdfsign.pkcs11.DigestAlgorithm customDigestAlgorithm = convertDigestAlgorithm(euDigestAlgorithm);
            log.debug("Digest Algorithm: " + customDigestAlgorithm.getName());

            // 使用token进行签名
            org.openpdfsign.pkcs11.SignatureValue customSignatureValue = token.sign(customToBeSigned, customDigestAlgorithm, signingKey);
            // 檢查簽名值
            if (customSignatureValue == null || customSignatureValue.getValue() == null) {
               throw new IOException("HSM returned invalid signature value");
            }

             // Determine EncryptionAlgorithm based on the key type
             String keyAlgorithmString = signingKey.getEncryptionAlgorithm();
             EncryptionAlgorithm encryptionAlgorithm;
             if (keyAlgorithmString != null && (keyAlgorithmString.toUpperCase().contains("EC") || keyAlgorithmString.toUpperCase().contains("ECDSA"))) {
                 encryptionAlgorithm = EncryptionAlgorithm.ECDSA;
                 log.debug("Determined encryption algorithm: ECDSA for key type: " + keyAlgorithmString);

                 // 对于ECDSA签名，需要将P1363格式转换为ASN.1 DER格式
                 byte[] derSignature = convertECDSASignatureP1363ToDER(customSignatureValue.getValue());
                 log.debug("Converted ECDSA signature from P1363 to DER format. Original length: " +
                          customSignatureValue.getValue().length + ", DER length: " + derSignature.length);
                 customSignatureValue = new org.openpdfsign.pkcs11.SignatureValue(customDigestAlgorithm, derSignature);
             } else if (keyAlgorithmString != null && keyAlgorithmString.toUpperCase().contains("RSA")) {
                 encryptionAlgorithm = EncryptionAlgorithm.RSA;
                 log.debug("Determined encryption algorithm: RSA for key type: " + keyAlgorithmString);
             } else {
                 log.warn("Unknown or null key algorithm: " + keyAlgorithmString + ". Defaulting to RSA. This might cause issues.");
                 encryptionAlgorithm = EncryptionAlgorithm.RSA; // Defaulting to RSA as a fallback
             }

            // // Create EU DSS SignatureValue using the determined encryption algorithm// 轉換為 DSS SignatureValue
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, euDigestAlgorithm);
            eu.europa.esig.dss.model.SignatureValue euSignatureValue = new eu.europa.esig.dss.model.SignatureValue(signatureAlgorithm, customSignatureValue.getValue());

            // 完成文档签名
            DSSDocument signedDocument = service.signDocument(toSignDocument, signatureParameters, euSignatureValue);

            // 保存签名后的文档
            if (binaryOutput != null) {
                signedDocument.writeTo(binaryOutput);
            } else {
                signedDocument.save(outputFile.toAbsolutePath().toString());
            }
            log.debug("Signature value: " + Arrays.toString(customSignatureValue.getValue()));

        } catch (Exception e) {
            throw new IOException("Error signing PDF: " + e.getMessage(), e);
        }
    }

    /**
     * Converts EU DSS DigestAlgorithm to custom DigestAlgorithm
     */
    private org.openpdfsign.pkcs11.DigestAlgorithm convertDigestAlgorithm(eu.europa.esig.dss.enumerations.DigestAlgorithm euAlgorithm) {
        switch (euAlgorithm.getName()) {
            case "SHA1":
                return org.openpdfsign.pkcs11.DigestAlgorithm.SHA1;
            case "SHA256":
                return org.openpdfsign.pkcs11.DigestAlgorithm.SHA256;
            case "SHA384":
                return org.openpdfsign.pkcs11.DigestAlgorithm.SHA384;
            case "SHA512":
                return org.openpdfsign.pkcs11.DigestAlgorithm.SHA512;
            default:
                return org.openpdfsign.pkcs11.DigestAlgorithm.SHA256; // Default
        }
    }

    /**
     * Creates a TSP source for the given URL
     */
    private OnlineTSPSource buildTspSource(String source, ProxyConfig proxyConfig) {
        TimestampDataLoader timestampDataLoader = new TimestampDataLoader();
        timestampDataLoader.setProxyConfig(proxyConfig);
        return new OnlineTSPSource(source, timestampDataLoader);
    }

    /**
     * 将ECDSA签名从P1363格式（r和s值的简单连接）转换为ASN.1 DER格式
     * P1363格式是PKCS#11令牌返回的原始格式，而PDF验证需要ASN.1 DER格式
     *
     * @param p1363Signature ECDSA签名的P1363格式（r和s值的简单连接）
     * @return ECDSA签名的ASN.1 DER格式
     */
    private byte[] convertECDSASignatureP1363ToDER(byte[] p1363Signature) {
        try {
            // P1363格式是r和s值的简单连接，每个值占据签名字节数组的一半
            int halfLength = p1363Signature.length / 2;

            // 提取r和s值
            byte[] rBytes = Arrays.copyOfRange(p1363Signature, 0, halfLength);
            byte[] sBytes = Arrays.copyOfRange(p1363Signature, halfLength, p1363Signature.length);

            // 转换为BigInteger（注意：BigInteger构造函数将字节数组视为有符号的，因此我们需要确保正确处理）
            BigInteger r = new BigInteger(1, rBytes);
            BigInteger s = new BigInteger(1, sBytes);

            // 创建ASN.1 DER序列
            ASN1EncodableVector vector = new ASN1EncodableVector();
            vector.add(new ASN1Integer(r));
            vector.add(new ASN1Integer(s));
            DERSequence sequence = new DERSequence(vector);

            // 编码为DER格式
            return sequence.getEncoded();
        } catch (Exception e) {
            log.error("Error converting ECDSA signature from P1363 to DER format: " + e.getMessage(), e);
            // 如果转换失败，返回原始签名
            return p1363Signature;
        }
    }

    // 添加一些必要的辅助方法来分解原始signPdf方法的功能
    private void configureSignatureParameters(PAdESSignatureParameters signatureParameters,
                                              SignatureParameters params) {
        // 从原始signPdf方法中提取签名参数配置逻辑
        if (params.getUseLT()) {
            signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
            signatureParameters.setContentSize((int) (SignatureOptions.DEFAULT_SIGNATURE_SIZE * 5.0)); // Increased from 1.5 to 2.5
        } else if (params.getUseLTA()) {
            signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
            signatureParameters.setContentSize((int) (SignatureOptions.DEFAULT_SIGNATURE_SIZE * 6.0)); // Increased from 1.75 to 3.0
        } else if (params.getUseTimestamp() || !params.getTSA().isEmpty()) {
            signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
            signatureParameters.setContentSize((int) (SignatureOptions.DEFAULT_SIGNATURE_SIZE * 7.5));
        } else {
            signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        }

        // 设置其他参数
        if (!Strings.isStringEmpty(params.getLocation())) {
            signatureParameters.setLocation(params.getLocation());
        }
        if (!Strings.isStringEmpty(params.getReason())) {
            signatureParameters.setReason(params.getReason());
        }
        if (!Strings.isStringEmpty(params.getContact())) {
            signatureParameters.setContactInfo(params.getContact());
        }
        signatureParameters.setAppName("open-pdf-sign");
    }
//    private void signPdfWithToken(Path pdfFile, Path outputFile, OutputStream binaryOutput,
//                                 SignatureParameters params, SignatureTokenConnection token,
//                                 DSSPrivateKeyEntry signingKey) throws IOException {
//        log.debug("Using provided token and key for signing");
//
//        // The JKSSignatureToken passed to this method is already set up to use the HSM for signing,
//        // so we can just call the parent signPdf method with a dummy keystore and password.
//        // The actual signing will be done by the token's overridden sign method.
//        byte[] dummyKeystore = new byte[0];
//        char[] dummyPassword = "dummy".toCharArray();
//
//        // Call the parent signPdf method with the dummy keystore and password
//        // The JKSSignatureToken we created in signPdfWithHsm will be used for the actual signing
//        super.signPdf(pdfFile, outputFile, dummyKeystore, dummyPassword, binaryOutput, params);
//    }
//
//    protected void signPdfWithToken(Path pdfFile, Path outputFile,
//                                    OutputStream binaryOutput,
//                                    SignatureParameters params,
//                                    SignatureTokenConnection token,
//                                    DSSPrivateKeyEntry signingKey) throws IOException {
//        try {
//            // 加载PDF文档
//            DSSDocument toSignDocument = new FileDocument(pdfFile.toFile());
//
//            // 创建签名参数
//            PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
//            signatureParameters.setSigningCertificate(signingKey.getCertificate());
//            signatureParameters.setCertificateChain(signingKey.getCertificateChain());
//
//            // 设置签名级别和其他参数
//            configureSignatureParameters(signatureParameters, params);
//
//            // 创建签名服务
//            PAdESService service = createPAdESService(params);
//
//            // 获取要签名的数据
//            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
//
//            // 使用token进行签名
//            SignatureValue signatureValue = token.sign(dataToSign,
//                    signatureParameters.getDigestAlgorithm(),
//                    signingKey);
//
//            // 完成签名并保存文档
//            DSSDocument signedDocument = service.signDocument(toSignDocument,
//                    signatureParameters,
//                    signatureValue);
//
//            if (binaryOutput != null) {
//                signedDocument.writeTo(binaryOutput);
//            } else {
//                signedDocument.save(outputFile.toAbsolutePath().toString());
//            }
//
//        } catch (Exception e) {
//            throw new IOException("Error signing PDF: " + e.getMessage(), e);
//        }
//    }

}
