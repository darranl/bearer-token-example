/*
 * Copyright The WildFly Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.wildfly.security.example.bearertoken.issuer;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Date;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class TokenIssuer {

    /**
     * The key that will be used to sign any issued JWTs.
     */
    private final PrivateKey privateKey;

    /**
     * Create a new {@code TokenIssuer} instance using the configuration
     * from the provided {@code Builder}.
     *
     * @param builder
     */
    TokenIssuer(final Builder builder) throws Exception {
        this.privateKey = loadPrivateKey(builder);
    }

    public String issueToken(final String username) throws Exception {
        Date expirationDate = new Date(new Date().getTime() + 10000);
        JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();

        claimsSet.subject("123445667");
        claimsSet.claim("username", username);
        claimsSet.audience("resource-server");
        claimsSet.issuer("elytron.org");
        claimsSet.expirationTime(expirationDate);

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet.build());

        signedJWT.sign(new RSASSASigner(privateKey));

        return signedJWT.serialize();
    }

    private static PrivateKey loadPrivateKey(final Builder builder) throws IOException,
                                                             GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream is = new FileInputStream(builder.keyStoreFile)) {
            keyStore.load(is, builder.keyStorePassword);

            Key key = keyStore.getKey(builder.keyAlias, builder.keyPassword);

            return (PrivateKey) key;
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private String keyAlias;
        private char[] keyPassword;
        private char[] keyStorePassword;
        private File keyStoreFile;

        public Builder setKeyAlias(final String keyAlias) {
            this.keyAlias = keyAlias;

            return this;
        }

        public Builder setKeyPassword(final char[] keyPassword) {
            this.keyPassword = keyPassword;

            return this;
        }

        public Builder setKeyStorePassword(final char[] keyStorePassword) {
            this.keyStorePassword = keyStorePassword;

            return this;
        }

        public Builder setKeyStoreFile(final File keyStoreFile) {
            this.keyStoreFile = keyStoreFile;

            return this;
        }

        public TokenIssuer build() throws Exception {
            // Guarantee all fields initialised to a value.
            if (keyStoreFile == null) {
                keyStoreFile = new File("keys.keystore");
            }
            if (keyAlias == null) {
                keyAlias = "issuer";
            }
            if (keyStorePassword == null) {
                keyStorePassword = "password".toCharArray();
            }
            if (keyPassword == null) {
                keyPassword = keyStorePassword;
            }
            return new TokenIssuer(this);
        }
    }

    /*
     * Options
     */
    private static final String KEYSTORE_OPTION = "-keystore";
    private static final String ALIAS_OPTION = "-alias";
    private static final String STORE_PASSWORD_OPTION = "-store-password";
    private static final String KEY_PASSWORD_OPTION = "-key-password";

    private static final String USERNAME_OPTION = "-username";

    public static void main(String[] args) throws Exception {
        Builder builder = builder();
        String username = "ladybird";

        int pos = 0;
        while (pos + 1 <= args.length) {
            String argument = args[pos++];
            switch (argument) {
                case(KEYSTORE_OPTION):
                    builder.setKeyStoreFile(new File(getString(args, pos, KEYSTORE_OPTION)));
                    break;
                case (ALIAS_OPTION):
                    builder.setKeyAlias(getString(args, pos, ALIAS_OPTION));
                    break;
                case STORE_PASSWORD_OPTION:
                    builder.setKeyStorePassword(getString(args, pos, STORE_PASSWORD_OPTION).toCharArray());
                    break;
                case KEY_PASSWORD_OPTION:
                    builder.setKeyPassword(getString(args, pos, KEY_PASSWORD_OPTION).toCharArray());
                    break;
                case USERNAME_OPTION:
                    username = getString(args, pos, USERNAME_OPTION);
                    break;
                default:
                    throw new IllegalArgumentException(String.format("Unrecognised option '%s'", argument));
            }
            pos++;
        }

        TokenIssuer issuer = builder.build();

        String token = issuer.issueToken(username);

        System.out.println("Generated JWT Token: ");
        System.out.println(token);
    }

    private static String getString(String[] args, int pos, String parameter) {
        if (pos > args.length - 1) {
            throw new IllegalArgumentException(String.format("Missing argument for '%s'", parameter));
        }

        return args[pos];
    }
}
