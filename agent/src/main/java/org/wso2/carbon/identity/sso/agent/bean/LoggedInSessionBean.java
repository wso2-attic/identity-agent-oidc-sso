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

import java.io.Serializable;

import org.json.JSONObject;

public class LoggedInSessionBean implements Serializable {

    private static final long serialVersionUID = 7762835859870143767L;

    private OIDC oidc;

    public OIDC getOIDC() {
        return oidc;
    }

    public void setOIDC(OIDC oidc) {
        this.oidc = oidc;
    }

    public class OIDC implements Serializable {

        private String callbackUrl;
        private String accessToken;
        private String refreshToken;
        private String idToken;
        private String code;
        private String sessionState;
        private JSONObject userDetails;

        public String getCallbackUrl() {
            return callbackUrl;
        }

        public void setCallbackUrl(String callbackUrl) {
            this.callbackUrl = callbackUrl;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public void setAccessToken(String accessToken) {
            this.accessToken = accessToken;
        }

        public String getRefreshToken() {
            return refreshToken;
        }

        public void setRefreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
        }

        public String getIdToken() {
            return idToken;
        }

        public void setIdToken(String idToken) {
            this.idToken = idToken;
        }

        public String getCode() {
            return code;
        }

        public void setCode(String code) {
            this.code = code;
        }

        public String getSessionState() {
            return sessionState;
        }

        public void setSessionState(String sessionState) {
            this.sessionState = sessionState;
        }

        public JSONObject getUserDetails() {
            return userDetails;
        }

        public void setUserDetails(JSONObject userDetails) {
            this.userDetails = userDetails;
        }

    }

}
