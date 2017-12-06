/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.sso.agent.bean;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.sso.agent.AESDecryptor;
import org.wso2.carbon.identity.sso.agent.util.SSOAgentConstants;
import org.wso2.carbon.identity.sso.agent.exception.SSOAgentException;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;

import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class SSOAgentConfig {

    private static final Logger LOGGER = Logger.getLogger(SSOAgentConstants.LOGGER_NAME);
    private static final String ARGUMENT = "sun.java.command";

    private Boolean isOIDCLoginEnabled = false;
    private Boolean isDynamicAppRegistrationEnabled = false;
    private Boolean isDynamicOIDCConfigEnabled = false;
    private String oidcURL = null;
    private Set<String> skipURIs = new HashSet<String>();
    private OIDC oidc = new OIDC();
    private Boolean enableHostNameVerification = false;
    private Boolean enableSSLVerification = false;
    private InputStream keyStoreStream;
    private String keyStorePassword;
    private KeyStore keyStore;
    private String privateKeyPassword;
    private String privateKeyAlias;
    private String idpPublicCertAlias;

    public SSOAgentConfig() {

    }

    public SSOAgentConfig(Properties properties) {
        try {
            initConfig(properties);
        } catch (SSOAgentException e) {
            LOGGER.log(Level.INFO, "An error occurred during SSO Agent Configuration. Cannot proceed further.");
        }
    }


    public Boolean getEnableHostNameVerification() {
        return enableHostNameVerification;
    }

    public Boolean getEnableSSLVerification() {
        return enableSSLVerification;
    }

    public Boolean isOIDCLoginEnabled() {
        return isOIDCLoginEnabled;
    }

    public Boolean isDynamicAppRegistrationEnabled() {
        return isDynamicAppRegistrationEnabled;
    }

    public void setDynamicAppRegistrationEnabled(String isDynamicAppRegistrationEnabledString) {

        if (isDynamicAppRegistrationEnabledString != null) {
            isDynamicAppRegistrationEnabled = Boolean.parseBoolean(isDynamicAppRegistrationEnabledString);
        } else {
            LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.ENABLE_DYNAMIC_APP_REGISTRATION +
                    " not configured. Defaulting to \'false\'");
            isDynamicAppRegistrationEnabled = false;
        }
    }

    public Boolean isDynamicOIDCConfigEnabled() {
        return isDynamicOIDCConfigEnabled;
    }

    public void setIsDynamicOIDCConfigEnabled(String isDynamicOIDCConfigEnabledString) {
        if (isDynamicOIDCConfigEnabledString != null) {
            isDynamicOIDCConfigEnabled = Boolean.parseBoolean(isDynamicOIDCConfigEnabledString);
        } else {
            LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.ENABLE_DYNAMIC_OIDC_CONFIGURATION +
                    " not configured. Defaulting to \'false\'");
            isDynamicOIDCConfigEnabled = false;
        }
    }

    public String getOIDCSSOURL() {
        return oidcURL;
    }

    public void setOIDCSSOURL(String oidcURL) {
        this.oidcURL = oidcURL;
    }

    public Set<String> getSkipURIs() {
        return skipURIs;
    }

    public void setSkipURIs(String skipURIsString) {
        if (!StringUtils.isBlank(skipURIsString)) {
            String[] skipURIArray = skipURIsString.split(",");
            for (String skipURI : skipURIArray) {
                skipURIs.add(skipURI);
            }
        }

    }

    public OIDC getOIDC() {
        return oidc;
    }

    public void setOIDCLoginEnabled(String isOIDCSSOLoginEnabledString) {
        if (isOIDCSSOLoginEnabledString != null) {
            isOIDCLoginEnabled = Boolean.parseBoolean(isOIDCSSOLoginEnabledString);
        } else {
            LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.ENABLE_OIDC_SSO_LOGIN +
                    " not configured. Defaulting to \'false\'");
            isOIDCLoginEnabled = false;
        }
    }

    public void setEnableSSLVerification(String enableSSLVerificationString) {
        if (enableSSLVerificationString != null) {
            this.enableSSLVerification = Boolean.parseBoolean(enableSSLVerificationString);
        } else {
            this.enableSSLVerification = false;
        }
    }

    public void setEnableHostNameVerification(String enableHostNameVerificationString) {
        if (enableHostNameVerificationString != null) {
            this.enableHostNameVerification = Boolean.parseBoolean(enableHostNameVerificationString);
        } else {
            this.enableHostNameVerification = false;
        }
    }

    private InputStream getKeyStoreStream() {
        return keyStoreStream;
    }

    public void setKeyStoreStream(String keyStore) throws SSOAgentException {
        if (keyStore != null) {
            try {
                keyStoreStream = new FileInputStream(keyStore);
            } catch (FileNotFoundException e) {
                throw new SSOAgentException("Cannot find file " + keyStore, e);
            }
        }
    }

    public String getPrivateKeyPassword() {
        return privateKeyPassword;
    }

    public String getPrivateKeyAlias() {
        return privateKeyAlias;
    }

    public String getIdPPublicCertAlias() {
        return idpPublicCertAlias;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public KeyStore getKeyStore() throws org.wso2.carbon.identity.sso.agent.exception.SSOAgentException {
        if (keyStore == null) {
            setKeyStore(readKeyStore(getKeyStoreStream(), getKeyStorePassword()));
        }
        return keyStore;
    }

    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    private void initConfig(Properties properties) throws SSOAgentException {

        decryptEncryptedProperties(properties);

        privateKeyPassword = properties.getProperty(SSOAgentConstants.PRIVATE_KEY_PASSWORD);
        privateKeyAlias = properties.getProperty(SSOAgentConstants.PRIVATE_KEY_ALIAS);
        idpPublicCertAlias = properties.getProperty(SSOAgentConstants.IDP_PUBLIC_CERT_ALIAS);

        setEnableSSLVerification(properties.getProperty(SSOAgentConstants.SSL.ENABLE_SSL_VERIFICATION));
        setEnableHostNameVerification(properties.getProperty(SSOAgentConstants.SSL.ENABLE_SSL_HOST_NAME_VERIFICATION));

        setOIDCLoginEnabled(properties.getProperty(SSOAgentConstants.SSOAgentConfig.ENABLE_OIDC_SSO_LOGIN));
        setDynamicAppRegistrationEnabled(properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.ENABLE_DYNAMIC_APP_REGISTRATION));
        setIsDynamicOIDCConfigEnabled(properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.ENABLE_DYNAMIC_OIDC_CONFIGURATION));
        setSkipURIs(properties.getProperty(SSOAgentConstants.SSOAgentConfig.SKIP_URIS));

        setOIDCSSOURL(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC_SSO_URL));
        performOIDCSpecificConfigurations(properties, oidc);

        setKeyStoreStream(properties.getProperty(SSOAgentConstants.KEY_STORE));
        setKeyStorePassword(properties.getProperty(SSOAgentConstants.KEY_STORE_PASSWORD));

        initializeSSLContext();
    }

    private void performOIDCSpecificConfigurations(Properties properties, OIDC oidc) throws SSOAgentException {
        oidc.setSpName(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.SERVICE_PROVIDER_NAME));
        oidc.setClientId(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.CLIENT_ID));
        oidc.setClientSecret(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.CLIENT_SECRET));
        oidc.setCallBackUrl(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.CALL_BACK_URL));
        oidc.setAuthzEndpoint(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.OAUTH2_AUTHZ_ENDPOINT));
        oidc.setTokenEndpoint(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.OAUTH2_TOKEN_ENDPOINT));
        oidc.setUserInfoEndpoint(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.OAUTH2_USER_INFO_ENDPOINT));
        oidc.setAuthzGrantType(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.OAUTH2_GRANT_TYPE));
        oidc.setOIDCLogoutEndpoint(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.OIDC_LOGOUT_ENDPOINT));
        oidc.setIsIDTokenValidationEnabled(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.
                ENABLE_ID_TOKEN_VALIDATION));
        oidc.setScope(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.SCOPE));
        oidc.setSessionIFrameEndpoint(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.
                OIDC_SESSION_IFRAME_ENDPOINT));
        oidc.setPostLogoutRedirectUri(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC
                .POST_LOGOUT_REDIRECT_URI));
    }

    private void decryptEncryptedProperties(Properties properties) throws SSOAgentException {
        String decodedPassword;
        boolean isReadPassword = false;
        char[] password = null;

        // Get copy of properties for looping in order to avoid ConcurrentModificationException.
        Properties copyOfProperties = new Properties();
        copyOfProperties.putAll(properties);

        // Path of the password file.
        String filePath = System.getProperty("catalina.home") + SSOAgentConstants.SSOAgentConfig.PASSWORD_FILEPATH;

        // Looping through properties to check the encrypted property value by checking the prefix Enc:.
        for (Map.Entry<Object, Object> entry : copyOfProperties.entrySet()) {
            if (String.valueOf(entry.getValue()).startsWith("Enc:")) {
                if (!System.getProperty(ARGUMENT).contains("password")) {

                    // Check whether the password has been already read.
                    if (!isReadPassword) {
                        Path path = Paths.get(filePath);
                        try (BufferedReader reader = Files.newBufferedReader(path, Charset.forName("UTF-8"))) {
                            StringBuilder currentLine = new StringBuilder();

                            // Read the password from the password file.
                            currentLine.append(reader.readLine());
                            if (currentLine.length() > 0) {
                                password = new char[currentLine.length()];
                                currentLine.getChars(0, currentLine.length(), password, 0);
                                currentLine = null;
                            }
                            isReadPassword = true;
                            if (Files.deleteIfExists(path)) {
                                LOGGER.info("Deleted the temporary password file at " + path);
                            }
                        } catch (IOException ex) {
                            throw new SSOAgentException("Error while reading the file ", ex);
                        }
                    }
                } else if (!isReadPassword) {

                    // Read password from the console.
                    System.out.print("Enter password for decryption:");
                    password = System.console().readPassword();
                    isReadPassword = true;
                }
                if (ArrayUtils.isEmpty(password)) {
                    LOGGER.log(Level.SEVERE, "Can't find the password to decrypt the encrypted values.");
                    return;
                }

                // Get the encrypted property value.
                String encryptedValue = String.valueOf(entry.getValue());

                // Remove the Enc: prefix and get the actual encrypted value.
                if (encryptedValue.split(":").length > 1) {
                    decodedPassword = AESDecryptor.decrypt(String.valueOf(entry.getValue()).split
                            (":")[1].trim(), password);

                    // Remove the encrypted property value and replace with decrypted property value (plain text)
                    properties.remove(String.valueOf(entry.getKey()));
                    properties.setProperty(String.valueOf(entry.getKey()), decodedPassword);
                } else {
                    LOGGER.log(Level.SEVERE, "Encrypted value is not in the correct format. Encrypted value " +
                            "must contain the encrypted value with Enc: as prefix.");
                    return;
                }
            }
        }

        // Delete the stored password from memory by filling with zeros.
        if (password != null) {
            Arrays.fill(password, (char) 0);
        }
    }

    private void initializeSSLContext() throws SSOAgentException {
        try {
            // Get SSL context
            SSLContext sslContext = SSLContext.getInstance("SSL");
            doHostNameVerification();
            TrustManager[] trustManagers = doSSLVerification();

            sslContext.init(null, trustManagers, new SecureRandom());
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);

        } catch (Exception e) {
            throw new SSOAgentException("An error in initializing SSL Context");
        }
    }

    /**
     * get the key store instance
     *
     * @param is            KeyStore InputStream
     * @param storePassword password of key store
     * @return KeyStore instant
     * @throws org.wso2.carbon.identity.sso.agent.exception.SSOAgentException if fails to load key store
     */
    private KeyStore readKeyStore(InputStream is, String storePassword) throws
            org.wso2.carbon.identity.sso.agent.exception.SSOAgentException {

        if (storePassword == null) {
            throw new org.wso2.carbon.identity.sso.agent.exception.SSOAgentException("KeyStore password can not be null");
        }

        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(is, storePassword.toCharArray());
            return keyStore;
        } catch (Exception e) {

            throw new org.wso2.carbon.identity.sso.agent.exception.SSOAgentException("Error while loading key store file", e);
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException ignored) {

                    throw new org.wso2.carbon.identity.sso.agent.exception.SSOAgentException("Error while closing input stream of key store", ignored);
                }
            }
        }
    }

    private void doHostNameVerification() {
        if (!this.getEnableHostNameVerification()) {
            // Create empty HostnameVerifier
            HostnameVerifier hv = new HostnameVerifier() {
                public boolean verify(String urlHostName, SSLSession session) {
                    return true;
                }
            };
            HttpsURLConnection.setDefaultHostnameVerifier(hv);
        }
    }

    private TrustManager[] doSSLVerification() throws Exception {
        TrustManager[] trustManagers = null;
        if (this.getEnableSSLVerification()) {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(this.getKeyStore());
            trustManagers = tmf.getTrustManagers();
        } else {
            // Create a trust manager that does not validate certificate chains
            trustManagers = new TrustManager[]{new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(java.security.cert.X509Certificate[] certs,
                                               String authType) {
                }

                public void checkServerTrusted(java.security.cert.X509Certificate[] certs,
                                               String authType) {
                }
            }};
        }
        return trustManagers;
    }

    public class OIDC {

        private String spName = StringUtils.EMPTY;
        private String clientId = StringUtils.EMPTY;
        private String clientSecret = StringUtils.EMPTY;
        private String authzEndpoint = StringUtils.EMPTY;
        private String tokenEndpoint = StringUtils.EMPTY;
        private String userInfoEndpoint = StringUtils.EMPTY;
        private String authzGrantType = StringUtils.EMPTY;
        private String callBackUrl = StringUtils.EMPTY;
        private String OIDCLogoutEndpoint = StringUtils.EMPTY;
        private String sessionIFrameEndpoint = StringUtils.EMPTY;
        private String scope = StringUtils.EMPTY;
        private String postLogoutRedirectUri = StringUtils.EMPTY;
        private Boolean isIDTokenValidationEnabled = false;

        public String getSpName() {
            return spName;
        }

        public void setSpName(String spName) throws SSOAgentException {
            if (StringUtils.isBlank(spName)) {
                throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.OIDC.SERVICE_PROVIDER_NAME
                        + "is not specified. Use either .properties file or context-params in web.xml to Specify the" +
                        " property. Cannot proceed further.");
            }
            this.spName = spName;
        }

        public Boolean getIsIDTokenValidationEnabled() {
            return isIDTokenValidationEnabled;
        }

        public void setIsIDTokenValidationEnabled(String enableIDTokenValidationString) {
            if (StringUtils.isNotBlank(enableIDTokenValidationString)) {
                this.isIDTokenValidationEnabled = Boolean.parseBoolean(enableIDTokenValidationString);
            } else {
                LOGGER.log(Level.FINE, "\'" + SSOAgentConstants.SSOAgentConfig.OIDC.ENABLE_ID_TOKEN_VALIDATION +
                        "\' not configured. Defaulting to \'false\'");
                this.isIDTokenValidationEnabled = false;
            }
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) throws SSOAgentException {
            if (StringUtils.isBlank(clientId)) {
                throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.OIDC.CLIENT_ID
                        + "is not specified. Use either .properties file or context-params in web.xml to Specify the" +
                        " property. Cannot proceed further.");
            }
            this.clientId = clientId;
        }

        public String getAuthzEndpoint() {
            return authzEndpoint;
        }

        public void setAuthzEndpoint(String authzEndpoint) {
            this.authzEndpoint = authzEndpoint;
        }

        public String getUserInfoEndpoint() {
            return userInfoEndpoint;
        }

        public void setUserInfoEndpoint(String userInfoEndpoint) {
            this.userInfoEndpoint = userInfoEndpoint;
        }

        public String getAuthzGrantType() {
            return authzGrantType;
        }

        public void setAuthzGrantType(String authzGrantType) {
            this.authzGrantType = authzGrantType;
        }

        public String getCallBackUrl() {
            return callBackUrl;
        }

        public void setCallBackUrl(String callBackUrl) throws SSOAgentException {
            if (StringUtils.isBlank(callBackUrl)) {
                throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.OIDC.CALL_BACK_URL
                        + "is not specified. Use either .properties file or context-params in web.xml to Specify the" +
                        " property. Cannot proceed further.");
            }
            this.callBackUrl = callBackUrl;
        }

        public String getScope() {
            return scope;
        }

        public void setScope(String scope) {
            this.scope = scope;
        }

        public String getOIDCLogoutEndpoint() {
            return OIDCLogoutEndpoint;
        }

        public void setOIDCLogoutEndpoint(String OIDCLogoutEndpoint) {
            this.OIDCLogoutEndpoint = OIDCLogoutEndpoint;
        }

        public String getSessionIFrameEndpoint() {
            return sessionIFrameEndpoint;
        }

        public void setSessionIFrameEndpoint(String sessionIFrameEndpoint) {
            this.sessionIFrameEndpoint = sessionIFrameEndpoint;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) throws SSOAgentException {
            if (StringUtils.isBlank(clientSecret)) {
                throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.OIDC.CLIENT_SECRET
                        + "is not specified. Use either .properties file or context-params in web.xml to Specify the" +
                        " property. Cannot proceed further.");
            }
            this.clientSecret = clientSecret;
        }

        public String getTokenEndpoint() {
            return tokenEndpoint;
        }

        public void setTokenEndpoint(String tokenEndpoint) {
            this.tokenEndpoint = tokenEndpoint;
        }

        public String getPostLogoutRedirectUri() {
            return postLogoutRedirectUri;
        }

        public void setPostLogoutRedirectUri(String postLogoutRedirectUri) {
            this.postLogoutRedirectUri = postLogoutRedirectUri;
        }
    }

}
