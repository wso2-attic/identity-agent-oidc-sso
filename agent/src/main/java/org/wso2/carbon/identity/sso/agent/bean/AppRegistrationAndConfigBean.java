/*
 * Copyright 2017 WSO2.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.sso.agent.bean;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.rmi.RemoteException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.wso2.carbon.authenticator.stub.AuthenticationAdminStub;
import org.wso2.carbon.authenticator.stub.LoginAuthenticationExceptionException;
import org.wso2.carbon.identity.application.common.model.xsd.ApplicationBasicInfo;
import org.wso2.carbon.identity.application.common.model.xsd.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.xsd.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.xsd.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.stub.IdentityApplicationManagementServiceIdentityApplicationManagementException;
import org.wso2.carbon.identity.application.mgt.stub.IdentityApplicationManagementServiceStub;
import org.wso2.carbon.identity.oauth.stub.OAuthAdminServiceStub;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.sso.agent.exception.SSOAgentException;

public class AppRegistrationAndConfigBean {

    private static final Logger LOGGER = Logger.getLogger("looger");

    private String sessionCookie = "";
    private IdentityApplicationManagementServiceStub applicationMgtStub;
    private String appMgtEndPoint = "https://localhost:9443/services/IdentityApplicationManagementService";

    public AppRegistrationAndConfigBean() throws AxisFault, RemoteException, MalformedURLException, SSOAgentException {
        applicationMgtStub = new IdentityApplicationManagementServiceStub(appMgtEndPoint);
        authenticate();
    }

    private void authenticate() throws RemoteException, MalformedURLException, SSOAgentException {
        try {
            AuthenticationAdminStub authenticationStub = new AuthenticationAdminStub("https://localhost:9443/services/AuthenticationAdmin?wsdl");
            authenticationStub.login("admin", "admin", (new URL("https://localhost:9443/services/")).getHost());

            ServiceContext serviceContext = authenticationStub._getServiceClient()
                    .getLastOperationContext().getServiceContext();

            sessionCookie = (String) serviceContext.getProperty(HTTPConstants.COOKIE_STRING);

            ServiceClient client2 = applicationMgtStub._getServiceClient();
            Options option2 = client2.getOptions();
            option2.setManageSession(true);

            // set the session cookie of the previous call to AuthenticationAdmin service
            option2.setProperty(org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, sessionCookie);
        } catch (LoginAuthenticationExceptionException e) {
            throw new SSOAgentException("Error occured while trying to invoke login function with AuthenticationAdminStub!",e);
        }

    }

    public boolean checkAppRegistrationStatus(String spName) throws RemoteException, MalformedURLException, SSOAgentException {
        try {
            ApplicationBasicInfo[] appInfoArray = applicationMgtStub.getAllApplicationBasicInfo();
            for (ApplicationBasicInfo abf : appInfoArray) {
                if (spName.equals(abf.getApplicationName())) {
                    return true;
                }
            }
        } catch (IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            throw new SSOAgentException("Error in invoking IdentityApplicationManagementService"
                    + " while checking Application registration status for the provider :" + spName, e);
        }
        return false;
    }

    public boolean checkOIDCconfigurationStatus(String spName) throws RemoteException, SSOAgentException {
        try {
            ServiceProvider sp = applicationMgtStub.getApplication(spName);
            InboundAuthenticationConfig iac = sp.getInboundAuthenticationConfig();
            InboundAuthenticationRequestConfig[] iarc = iac.getInboundAuthenticationRequestConfigs();
            String inboundConfigs = "";
            for (InboundAuthenticationRequestConfig elem : iarc) {
                inboundConfigs += elem.getInboundAuthType() + " , ";
            }
            LOGGER.log(Level.INFO, inboundConfigs + " configured for Service Provider '" + spName + "'");
            return inboundConfigs.contains("openid") && inboundConfigs.contains("oauth2");

        } catch (IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            throw new SSOAgentException("Error occured while checking OIDC configuration "
                    + "status for application '" + spName + "':", e);
        }
    }

    public void performDynamicAppRegistration(String spName) throws MalformedURLException, RemoteException, SSOAgentException {
        try {
            ServiceProvider sp = new ServiceProvider();
            sp.setApplicationName(spName);
            sp.setDescription("Application was created in IDP via SSO Agent.");
            applicationMgtStub.createApplication(sp);
        } catch (IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            throw new SSOAgentException("Error occured while performing dynamic registration for application '"
                    + spName + "':", e);
        }
    }

    public String performDynamicOIDCConfiguration(SSOAgentConfig ssoAgentConfig) throws SSOAgentException, RemoteException, MalformedURLException, ProtocolException, IOException {
        try {
            Boolean sameConsumerKeyExists = false;
            ServiceProvider sp = applicationMgtStub.getApplication(ssoAgentConfig.getOIDC().getSpName());

            InboundAuthenticationConfig inboundAuthnConfig = new InboundAuthenticationConfig();
            InboundAuthenticationRequestConfig inAuthnReqConfig = new InboundAuthenticationRequestConfig();

            if (sp.isInboundAuthenticationConfigSpecified()) {
                InboundAuthenticationConfig iac = sp.getInboundAuthenticationConfig();
                InboundAuthenticationRequestConfig[] iarc = iac.getInboundAuthenticationRequestConfigs();
                for (InboundAuthenticationRequestConfig i : iarc) {
                    if ("samlsso".equals(i.getInboundAuthType())) {
                        return "SAML configuration is already Done for " + ssoAgentConfig.getOIDC().getSpName()
                                + ".Simultaneous SAML and OIDC configurations are not recommended.";
                    }
                }
            }
            inAuthnReqConfig.setInboundAuthKey(ssoAgentConfig.getOIDC().getSpName());
            inAuthnReqConfig.setInboundAuthType("oauth2");
            inboundAuthnConfig.addInboundAuthenticationRequestConfigs(inAuthnReqConfig);

            OAuthConsumerAppDTO oauthDTO = new OAuthConsumerAppDTO();
            oauthDTO.setCallbackUrl(ssoAgentConfig.getOIDC().getCallBackUrl());

            OAuthAdminServiceStub OAuthStub = new OAuthAdminServiceStub();

            for(OAuthConsumerAppDTO appDTO:OAuthStub.getAllOAuthApplicationData()){
                if(appDTO.getOauthConsumerKey().equals(ssoAgentConfig.getOIDC().getClientId())){
                    sameConsumerKeyExists = true;
                    return "Unable to perform Dynamic OIDC configuration since a Service provider" +
                            " is already registered with the CONSUMER KEY:"+ ssoAgentConfig.getOIDC().getClientId();
                }
            }

            if(!sameConsumerKeyExists){
                oauthDTO.setOauthConsumerKey(ssoAgentConfig.getOIDC().getClientId());
                oauthDTO.setOauthConsumerSecret(ssoAgentConfig.getOIDC().getClientSecret());

                oauthDTO.setOAuthVersion("OAuth-2.0");
                oauthDTO.setGrantTypes("authorization_code implicit password client_credentials refresh_token "
                        + "urn:ietf:params:oauth:grant-type:saml2-bearer iwa:ntlm");

                OAuthAdminServiceStub oauthStub = new OAuthAdminServiceStub();
                ServiceClient client4 = oauthStub._getServiceClient();
                Options option4 = client4.getOptions();
                option4.setManageSession(true);
                option4.setProperty(org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, sessionCookie);

                oauthStub.registerOAuthApplicationData(oauthDTO);
                sp.setInboundAuthenticationConfig(inboundAuthnConfig);

                applicationMgtStub.updateApplication(sp);
            }

        } catch (IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            throw new SSOAgentException("Error in invoking IdentityApplicationManagementService"
                    + " while performing dynamic OIDC configuration for the provider :" + 
                    ssoAgentConfig.getOIDC().getSpName(), e);
        } catch (Exception e) {
            throw new SSOAgentException("An error occured while performing dynamic OIDC "
                    + "configuration for the provider :" + ssoAgentConfig.getOIDC().getSpName(), e);
        }
        return "updated";
    }

}
