package com.scality.keycloak.longLivedToken;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import org.keycloak.common.util.KeyUtils;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.AbstractEcKeyProviderFactory;

final class LongLivedTokenSigningKeys {

    private static final int RSA_KEY_SIZE = 2048;

    private record KeySpec(String type, String curve) {
    }

    private static final Map<String, KeySpec> KEY_SPECS = Map.of(
            Algorithm.RS256, new KeySpec(KeyType.RSA, null),
            Algorithm.RS384, new KeySpec(KeyType.RSA, null),
            Algorithm.RS512, new KeySpec(KeyType.RSA, null),
            Algorithm.PS256, new KeySpec(KeyType.RSA, null),
            Algorithm.PS384, new KeySpec(KeyType.RSA, null),
            Algorithm.PS512, new KeySpec(KeyType.RSA, null),
            Algorithm.ES256, new KeySpec(KeyType.EC, "P-256"),
            Algorithm.ES384, new KeySpec(KeyType.EC, "P-384"),
            Algorithm.ES512, new KeySpec(KeyType.EC, "P-521"));

    private LongLivedTokenSigningKeys() {
    }

    static boolean isSupported(String algorithm) {
        return algorithm != null && KEY_SPECS.containsKey(algorithm);
    }

    static KeyPair generate(String algorithm) {
        KeySpec spec = spec(algorithm);
        if (spec.curve() == null) {
            return KeyUtils.generateRsaKeyPair(RSA_KEY_SIZE);
        }
        return AbstractEcKeyProviderFactory.generateEcKeyPair(
                AbstractEcKeyProviderFactory.convertECDomainParmNistRepToSecRep(spec.curve()));
    }

    static KeyWrapper signingKey(String kid, String algorithm, KeyPair keyPair) {
        KeyWrapper key = wrap(kid, algorithm, keyPair.getPublic());
        key.setPrivateKey(keyPair.getPrivate());
        key.setStatus(KeyStatus.ACTIVE);
        return key;
    }

    static KeyWrapper verificationKey(String kid, String algorithm, String encodedPublicKey)
            throws GeneralSecurityException {
        PublicKey publicKey = KeyFactory.getInstance(spec(algorithm).type())
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(encodedPublicKey)));
        return wrap(kid, algorithm, publicKey);
    }

    static String encode(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    private static KeyWrapper wrap(String kid, String algorithm, PublicKey publicKey) {
        KeySpec spec = spec(algorithm);
        KeyWrapper key = new KeyWrapper();
        key.setKid(kid);
        key.setAlgorithm(algorithm);
        key.setType(spec.type());
        key.setUse(KeyUse.SIG);
        // Passive: published and used to verify, never picked to sign other tokens.
        key.setStatus(KeyStatus.PASSIVE);
        key.setPublicKey(publicKey);
        key.setCurve(spec.curve());
        return key;
    }

    private static KeySpec spec(String algorithm) {
        if (!isSupported(algorithm)) {
            throw new IllegalArgumentException("Unsupported long-lived token algorithm " + algorithm);
        }
        return KEY_SPECS.get(algorithm);
    }
}
