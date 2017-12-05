/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 *
 *
 */

package org.wso2.carbon.identity.sso.agent.util;

public class SSOAgentConstants {

    public static final String LOGGER_NAME = "org.wso2.carbon.identity.sso.agent";

    public static final String SESSION_BEAN_NAME = "org.wso2.carbon.identity.sso.agent.LoggedInSessionBean";
    public static final String CONFIG_BEAN_NAME = "org.wso2.carbon.identity.sso.agent.SSOAgentConfig";
    public static final String SHOULD_GO_TO_WELCOME_PAGE = "shouldGoToWelcomePage";
    public static final String PROPERTY_FILE_PARAMETER_NAME = "property-file";
    public static final String CERTIFICATE_FILE_PARAMETER_NAME = "certificate-file";

    public static final String KEY_STORE_PASSWORD = "KeyStorePassword";
    public static final String IDP_PUBLIC_CERT_ALIAS = "IdPPublicCertAlias";
    public static final String PRIVATE_KEY_ALIAS = "PrivateKeyAlias";
    public static final String PRIVATE_KEY_PASSWORD = "PrivateKeyPassword";

    private SSOAgentConstants() {}

    public static class SSOAgentConfig {

        public static final String ENABLE_OIDC_SSO_LOGIN = "EnableOIDCSSOLogin";
        public static final String ENABLE_DYNAMIC_APP_REGISTRATION = "EnableDynamicAppRegistration";
        public static final String ENABLE_DYNAMIC_OIDC_CONFIGURATION = "EnableDynamicOIDCConfiguration";
        public static final String OIDC_SSO_URL = "OIDCSSOURL";
        public static final String SKIP_URIS = "SkipURIs";
        public static final String PASSWORD_FILEPATH = "/conf/password_temp.txt";

        private SSOAgentConfig() {}

        public static class OIDC {

            public static final String CLIENT_ID = "OIDC.ClientId";
            public static final String CLIENT_SECRET = "OIDC.ClientSecret";
            public static final String CALL_BACK_URL = "OIDC.CallBackUrl";
            public static final String SERVICE_PROVIDER_NAME = "OIDC.spName";
            public static final String OAUTH2_GRANT_TYPE = "OIDC.GrantType";
            public static final String OAUTH2_AUTHZ_ENDPOINT = "OIDC.AuthorizeEndpoint";
            public static final String OAUTH2_TOKEN_ENDPOINT = "OIDC.TokenEndpoint";
            public static final String OAUTH2_USER_INFO_ENDPOINT = "OIDC.UserInfoEndpoint";
            public static final String OIDC_LOGOUT_ENDPOINT = "OIDC.LogoutEndpoint";
            public static final String OIDC_SESSION_IFRAME_ENDPOINT = "OIDC.SessionIFrameEndpoint";
            public static final String SCOPE = "OIDC.Scope";
            public static final String POST_LOGOUT_REDIRECT_RUI = "OIDC.PostLogoutRedirectUri";
            public static final String ENABLE_ID_TOKEN_VALIDATION = "OIDC.EnableIDTokenValidation";

            private OIDC() {}
        }

    }

}
