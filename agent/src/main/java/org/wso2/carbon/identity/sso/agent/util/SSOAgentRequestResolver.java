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
package org.wso2.carbon.identity.sso.agent.util;

import javax.servlet.ServletRequest;
import org.wso2.carbon.identity.sso.agent.bean.SSOAgentConfig;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SSOAgentRequestResolver {

    SSOAgentConfig ssoAgentConfig = null;
    HttpServletRequest request = null;

    public SSOAgentRequestResolver(HttpServletRequest request, HttpServletResponse response,
                                   SSOAgentConfig ssoAgentConfig) {

        this.request = request;
        this.ssoAgentConfig = ssoAgentConfig;
    }

    public boolean isOIDCURL() {
        return ssoAgentConfig.isOIDCLoginEnabled() &&
                request.getRequestURI().endsWith(ssoAgentConfig.getOIDCSSOURL());
    }
    
    public boolean isOIDCCodeResponse(ServletRequest servletRequest){
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        if(request.getRequestURI().contains("callback") && request.getParameter("code")!= null)
        return true;
        
        else return false;
    }
    
    public boolean isOidcSLOURL(ServletRequest servletRequest){
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        if(request.getRequestURI().contains("callback")  && request.getParameter("code")== null)
            return true;
        
        else return false;
    }

    public boolean isURLToSkip() {
        return ssoAgentConfig.getSkipURIs().contains(request.getRequestURI());
    }
}
