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
package org.wso2.carbon.identity.sso.agent;

import org.wso2.carbon.identity.sso.agent.bean.SSOAgentConfig;
import org.wso2.carbon.identity.sso.agent.util.SSOAgentConstants;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

/**
 * Context Event Listener Class for OIDC SSO. This class is used to perform OIDC configurations.
 * Initialization is performed in the following order.
 * 1. assignment of default values
 * 2. fetch values from context-params defined in web.xml
 * 3. read properties from sso.properties file.
 */
public class SSOAgentContextEventListener implements ServletContextListener {

    private static Logger logger = Logger.getLogger(SSOAgentContextEventListener.class.getName());

    public static final String DEFAULT_SSO_PROPERTIES_FILE_NAME = "sso.properties";

    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        Properties ssoProperties = new Properties();
        ServletContext servletContext = servletContextEvent.getServletContext();
        loadSSOProperties(ssoProperties, servletContextEvent, getPropertyFileName(servletContext));

        SSOAgentConfig config = new SSOAgentConfig(ssoProperties);
        servletContext.setAttribute(SSOAgentConstants.CONFIG_BEAN_NAME, config);

    }


    private void loadSSOProperties(Properties ssoProperties, ServletContextEvent servletContextEvent,
                                   String propertyFileName) {
        loadDefaultValues(ssoProperties);
        readPropertiesFromContextParams(ssoProperties, servletContextEvent);
        readPropertiesFromPropertyFile(ssoProperties, servletContextEvent, propertyFileName);

        Enumeration effectivePropertyNames = ssoProperties.propertyNames();
        String effectivePropertiesString = "Final(Effective) Properties: ";
        String propertyName;
        while (effectivePropertyNames.hasMoreElements()) {
            propertyName = effectivePropertyNames.nextElement().toString();
            effectivePropertiesString += propertyName + " = " + ssoProperties.getProperty(propertyName) + ", ";
        }
        logger.log(Level.INFO, effectivePropertiesString);
    }

    private void readPropertiesFromPropertyFile(Properties ssoProperties, ServletContextEvent servletContextEvent,
                                                String propertyFileName) {
        Properties propertiesInPropertyFile = new Properties();

        try {
            propertiesInPropertyFile.load(servletContextEvent.getServletContext().
                    getResourceAsStream("/WEB-INF/classes/" + propertyFileName));
        } catch (IOException e) {
            logger.log(Level.INFO, String.format(" Error occurred while trying to load property file: %s",
                    propertyFileName));
        }

        Enumeration propertyFilePropertyNames = propertiesInPropertyFile.propertyNames();
        String propertyFilePropertyName;
        while (propertyFilePropertyNames.hasMoreElements()) {
            propertyFilePropertyName = propertyFilePropertyNames.nextElement().toString();
            if (ssoProperties.getProperty(propertyFilePropertyName) == null) {
                ssoProperties.setProperty(propertyFilePropertyName, propertiesInPropertyFile.
                        getProperty(propertyFilePropertyName));
            } else if (ssoProperties.getProperty(propertyFilePropertyName) != null) {
                ssoProperties.replace(propertyFilePropertyName, propertiesInPropertyFile.
                        getProperty(propertyFilePropertyName));
            }
        }
    }


    private void readPropertiesFromContextParams(Properties ssoProperties, ServletContextEvent servletContextEvent) {
        ServletContext servletContext = servletContextEvent.getServletContext();
        Enumeration parameterNames = servletContext.getInitParameterNames();
        String contextParamName;

        while (parameterNames.hasMoreElements()) {
            contextParamName = parameterNames.nextElement().toString();
            if (ssoProperties.getProperty(contextParamName) == null) {
                ssoProperties.setProperty(contextParamName, servletContext.getInitParameter(contextParamName));
            } else if (ssoProperties.getProperty(contextParamName) != null) {
                ssoProperties.replace(contextParamName, servletContext.getInitParameter(contextParamName));
            }
        }
    }

    private void loadDefaultValues(Properties ssoProperties) {
        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.ENABLE_OIDC_SSO_LOGIN, "true");
        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.OIDC_SSO_URL, "oidcsso");
        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.OIDC.OAUTH2_AUTHZ_ENDPOINT,
                "https://localhost:9443/oauth2/authorize");
        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.OIDC.OAUTH2_TOKEN_ENDPOINT,
                "https://localhost:9443/oauth2/token");
        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.OIDC.OAUTH2_USER_INFO_ENDPOINT,
                "https://localhost:9443/oauth2/userinfo?schema=openid");
        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.OIDC.OAUTH2_GRANT_TYPE, "code");
        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.OIDC.SCOPE, "openid");
        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.OIDC.ENABLE_ID_TOKEN_VALIDATION, "false");
        ssoProperties.setProperty(SSOAgentConstants.SSOAgentConfig.OIDC.OIDC_LOGOUT_ENDPOINT,
                "https://localhost:9443/oidc/logout");

        ssoProperties.setProperty(SSOAgentConstants.KEY_STORE_PASSWORD, "wso2carbon");
        ssoProperties.setProperty(SSOAgentConstants.IDP_PUBLIC_CERT_ALIAS, "wso2carbon");
        ssoProperties.setProperty(SSOAgentConstants.PRIVATE_KEY_ALIAS, "wso2carbon");
        ssoProperties.setProperty(SSOAgentConstants.PRIVATE_KEY_PASSWORD, "wso2carbon");
    }

    private String getPropertyFileName(ServletContext servletContext) {
        if (servletContext.getInitParameter(SSOAgentConstants.PROPERTY_FILE_PARAMETER_NAME) != null) {
            return servletContext.getInitParameter(SSOAgentConstants.PROPERTY_FILE_PARAMETER_NAME);
        }
        return DEFAULT_SSO_PROPERTIES_FILE_NAME;
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
    }

}
