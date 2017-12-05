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
import java.util.Arrays;
import java.util.HashMap;
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

    private Boolean isSAML2SSOLoginEnabled = false;
    private Boolean isOIDCLoginEnabled = false;
    private Boolean isOpenIdLoginEnabled = false;
    private Boolean isOAuth2SAML2GrantEnabled = false;
    private Boolean isDynamicAppRegistrationEnabled = false;
    private Boolean isDynamicSAMLConfigEnabled = false;
    private Boolean isDynamicOIDCConfigEnabled = false;

    private String saml2SSOURL = null;
    private String oidcURL = null;
    private String openIdURL = null;
    private String oauth2SAML2GrantURL = null;
    private Set<String> skipURIs = new HashSet<String>();

    private Map<String, String[]> queryParams = new HashMap<String, String[]>();


    private OIDC oidc = new OIDC();
    private Boolean enableHostNameVerification = false;
    private Boolean enableSSLVerification = false;
    private InputStream keyStoreStream;
    private String keyStorePassword;
    private KeyStore keyStore;
    private String privateKeyPassword;
    private String privateKeyAlias;
    private String idpPublicCertAlias;

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

    public void setDynamicAppRegistrationEnabled(Boolean isDynamicAppRegistrationEnabled) {
        this.isDynamicAppRegistrationEnabled = isDynamicAppRegistrationEnabled;
    }

    public Boolean isDynamicOIDCConfigEnabled() {
        return isDynamicOIDCConfigEnabled;
    }

    public void setIsDynamicOIDCConfigEnabled(Boolean isDynamicOIDCConfigEnabled) {
        this.isDynamicOIDCConfigEnabled = isDynamicOIDCConfigEnabled;
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

    public void setSkipURIs(Set<String> skipURIs) {
        this.skipURIs = skipURIs;
    }

    public OIDC getOIDC() { return oidc; }

    public void setOIDCLoginEnabled(Boolean isOIDCLoginEnabled) {
        this.isOIDCLoginEnabled = isOIDCLoginEnabled;
    }

    private InputStream getKeyStoreStream() {
        return keyStoreStream;
    }

    public void setKeyStoreStream(InputStream keyStoreStream) {
        if (this.keyStoreStream == null) {
            this.keyStoreStream = keyStoreStream;
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

    public void initConfig(Properties properties) throws SSOAgentException {

        String decodedPassword;
        boolean isReadpassword = false;
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
                    if (!isReadpassword) {
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
                            isReadpassword = true;
                            if (Files.deleteIfExists(path)) {
                                LOGGER.info("Deleted the temporary password file at " + path);
                            }
                        } catch (IOException ex) {
                            throw new SSOAgentException("Error while reading the file ", ex);
                        }
                    }
                } else if (!isReadpassword) {

                    // Read password from the console.
                    System.out.print("Enter password for decryption:");
                    password = System.console().readPassword();
                    isReadpassword = true;
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
        privateKeyPassword = properties.getProperty("PrivateKeyPassword");
        privateKeyAlias = properties.getProperty("PrivateKeyAlias");
        idpPublicCertAlias = properties.getProperty("IdPPublicCertAlias");
        if (properties.getProperty("SSL.EnableSSLVerification") != null) {
            enableSSLVerification = Boolean.parseBoolean(properties.getProperty("SSL.EnableSSLVerification"));
        }
        if (properties.getProperty("SSL.EnableSSLHostNameVerification") != null) {
            enableHostNameVerification =
                    Boolean.parseBoolean(properties.getProperty("SSL.EnableSSLHostNameVerification"));
        }
        

        String isOIDCSSOLoginEnabledString = properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.ENABLE_OIDC_SSO_LOGIN);
        if (isOIDCSSOLoginEnabledString != null) {
            isOIDCLoginEnabled = Boolean.parseBoolean(isOIDCSSOLoginEnabledString);
        } else {
            LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.ENABLE_OIDC_SSO_LOGIN +
                    " not configured. Defaulting to \'false\'");
            isOIDCLoginEnabled = false;
        }

        String isDynamicAppRegistrationEnabledString = properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.ENABLE_DYNAMIC_APP_REGISTRATION);
        
        if(isDynamicAppRegistrationEnabledString != null){
            isDynamicAppRegistrationEnabled = Boolean.parseBoolean(isDynamicAppRegistrationEnabledString);
        } else {
            LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.ENABLE_DYNAMIC_APP_REGISTRATION +
                    " not configured. Defaulting to \'false\'");
            isDynamicAppRegistrationEnabled  = false;
        }

        String isDynamicOIDCConfigEnabledString = properties.getProperty(
                SSOAgentConstants.SSOAgentConfig.ENABLE_DYNAMIC_OIDC_CONFIGURATION);
        if(isDynamicOIDCConfigEnabledString !=null){
            isDynamicOIDCConfigEnabled = Boolean.parseBoolean(isDynamicOIDCConfigEnabledString);
        }else {
            LOGGER.log(Level.FINE, SSOAgentConstants.SSOAgentConfig.ENABLE_DYNAMIC_OIDC_CONFIGURATION +
                    " not configured. Defaulting to \'false\'");
            isDynamicOIDCConfigEnabled  = false;
        }

        oidcURL = properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC_SSO_URL);

        String skipURIsString = properties.getProperty(SSOAgentConstants.SSOAgentConfig.SKIP_URIS);
        if (!StringUtils.isBlank(skipURIsString)) {
            String[] skipURIArray = skipURIsString.split(",");
            for (String skipURI : skipURIArray) {
                skipURIs.add(skipURI);
            }
        }

        //configurations for OIDC specific properties begins here....

        oidc.spName = properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.SERVICE_PROVIDER_NAME);
        if(StringUtils.isBlank(oidc.spName)){
            throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.OIDC.SERVICE_PROVIDER_NAME
                    + "is not specified. Use either .properties file or context-params in web.xml to Specify the" +
                    " property. Cannot proceed further.");
        }

        oidc.clientId = properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.CLIENT_ID);
        if(StringUtils.isBlank(oidc.clientId)){
            throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.OIDC.CLIENT_ID
                    + "is not specified. Use either .properties file or context-params in web.xml to Specify the" +
                    " property. Cannot proceed further.");
        }

        oidc.clientSecret = properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.CLIENT_SECRET);
        if(StringUtils.isBlank(oidc.clientSecret)){
            throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.OIDC.CLIENT_SECRET
                    + "is not specified. Use either .properties file or context-params in web.xml to Specify the" +
                    " property. Cannot proceed further.");
        }

        oidc.callBackUrl = properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.CALL_BACK_URL);
        if(StringUtils.isBlank(oidc.callBackUrl)){
            throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.OIDC.CALL_BACK_URL
                    + "is not specified. Use either .properties file or context-params in web.xml to Specify the" +
                    " property. Cannot proceed further.");
        }

        oidc.setAuthzEndpoint(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.OAUTH2_AUTHZ_ENDPOINT));
        oidc.setTokenEndpoint(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.OAUTH2_TOKEN_ENDPOINT));
        oidc.setUserInfoEndpoint(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.OAUTH2_USER_INFO_ENDPOINT));
        oidc.setAuthzGrantType(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.OAUTH2_GRANT_TYPE));
        oidc.setOIDCLogoutEndpoint(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.OIDC_LOGOUT_ENDPOINT));

        String enableIDTokenValidationString = properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.ENABLE_ID_TOKEN_VALIDATION);
        if(StringUtils.isNotBlank(enableIDTokenValidationString)){
            oidc.setIsIDTokenValidationEnabled(Boolean.parseBoolean(
                properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.ENABLE_ID_TOKEN_VALIDATION)));
        }else{
            LOGGER.log(Level.FINE, "\'" + SSOAgentConstants.SSOAgentConfig.OIDC.ENABLE_ID_TOKEN_VALIDATION +
                    "\' not configured. Defaulting to \'false\'");
            oidc.setIsIDTokenValidationEnabled(false);
        }
        
        oidc.setSessionIFrameEndpoint(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC
                .OIDC_SESSION_IFRAME_ENDPOINT));
        oidc.setScope(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC.SCOPE));
        oidc.setPostLogoutRedirectUri(properties.getProperty(SSOAgentConstants.SSOAgentConfig.OIDC
                .POST_LOGOUT_REDIRECT_RUI));

        if (properties.getProperty("KeyStore") != null) {
            try {
                keyStoreStream = new FileInputStream(properties.getProperty("KeyStore"));
            } catch (FileNotFoundException e) {
                throw new SSOAgentException("Cannot find file " + properties.getProperty("KeyStore"), e);
            }
        }
        keyStorePassword = properties.getProperty("KeyStorePassword");

        SSLContext sc;
        try {
            // Get SSL context
            sc = SSLContext.getInstance("SSL");
            doHostNameVerification();
            TrustManager[] trustManagers = doSSLVerification();

            sc.init(null, trustManagers, new java.security.SecureRandom());
            SSLSocketFactory sslSocketFactory = sc.getSocketFactory();
            HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);

        } catch (Exception e) {
            throw new SSOAgentException("An error in initializing SSL Context");
        }
    }

    public void verifyConfig() throws SSOAgentException {

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

    private void doHostNameVerification(){
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
            trustManagers = new TrustManager[] { new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(java.security.cert.X509Certificate[] certs,
                                               String authType) {
                }

                public void checkServerTrusted(java.security.cert.X509Certificate[] certs,
                                               String authType) {
                }
            } };
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

        public void setSpName(String spName) {
            this.spName = spName;
        }
        
        public Boolean getIsIDTokenValidationEnabled() {
            return isIDTokenValidationEnabled;
        }

        public void setIsIDTokenValidationEnabled(Boolean isIDTokenValidationEnabled) {
            this.isIDTokenValidationEnabled = isIDTokenValidationEnabled;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
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

        public void setCallBackUrl(String callBackUrl) {
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

        public void setClientSecret(String clientSecret) {
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
