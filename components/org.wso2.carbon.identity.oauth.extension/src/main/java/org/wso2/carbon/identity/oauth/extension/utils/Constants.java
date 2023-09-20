/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth.extension.utils;

/**
 * This class contains the constants used in the extension.
 */
public class Constants {

    public static final String OPENJDK_SCRIPT_CLASS_NAME = "org.openjdk.nashorn.api.scripting.ScriptObjectMirror";
    public static final String JDK_SCRIPT_CLASS_NAME = "jdk.nashorn.api.scripting.ScriptObjectMirror";
    public static final String OUTCOME_SUCCESS = "onSuccess";
    public static final String OUTCOME_FAIL = "onFail";
    public static final String OUTCOME_TIMEOUT = "onTimeout";
    public static final String CHOREO_DOMAINS = "AdaptiveAuth.ChoreoDomains.Domain";
    public static final String CHOREO_TOKEN_ENDPOINT = "AdaptiveAuth.ChoreoTokenEndpoint";
    public static final String CALL_CHOREO_HTTP_CONNECTION_TIMEOUT = "AdaptiveAuth.CallChoreo.HTTPConnectionTimeout";

    public static final String CALL_CHOREO_HTTP_CONNECTION_REQUEST_TIMEOUT
            = "AdaptiveAuth.CallChoreo.HTTPConnectionRequestTimeout";
    public static final String CALL_CHOREO_HTTP_READ_TIMEOUT = "AdaptiveAuth.CallChoreo.HTTPReadTimeout";
    public static final String ADD_TO_ACCESS_TOKEN = "addToAccessToken";
    public static final String ADD_TO_IDTOKEN = "addToIDToken";

    public static final String TYPE_APPLICATION_JSON = "application/json";
    public static final String TYPE_FORM_DATA = "application/x-www-form-urlencoded";
    public static final String AUTHORIZATION = "Authorization";
    public static final String GRANT_TYPE = "grant_type";
    public static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    public static final String URL_VARIABLE_NAME = "url";
    public static final String CONSUMER_KEY_VARIABLE_NAME = "consumerKey";
    public static final String CONSUMER_KEY_ALIAS_VARIABLE_NAME = "consumerKeyAlias";
    public static final String CONSUMER_SECRET_VARIABLE_NAME = "consumerSecret";
    public static final String CONSUMER_SECRET_ALIAS_VARIABLE_NAME = "consumerSecretAlias";
    public static final String ASGARDEO_TOKEN_ENDPOINT = "asgardeoTokenEndpoint";
    public static final String SECRET_TYPE = "ADAPTIVE_AUTH_CALL_CHOREO";
//    public static final String HTTP_READ_TIMEOUT = "AdaptiveAuth.HTTPReadTimeout";
//    public static final String HTTP_CONNECTION_REQUEST_TIMEOUT = "AdaptiveAuth.HTTPConnectionRequestTimeout";
//    public static final String HTTP_CONNECTION_TIMEOUT = "AdaptiveAuth.HTTPConnectionTimeout";
//    public static final String HTTP_FUNCTION_ALLOWED_DOMAINS = "AdaptiveAuth.HTTPFunctionAllowedDomains.Domain";


    public static final char DOMAIN_SEPARATOR = '.';
    public static final String ACCESS_TOKEN_KEY = "access_token";
    public static final int HTTP_STATUS_OK = 200;
    public static final int HTTP_STATUS_UNAUTHORIZED = 401;
    public static final String ERROR_CODE_ACCESS_TOKEN_INACTIVE = "900901";
    public static final String CODE = "code";
    public static final String JWT_EXP_CLAIM = "exp";
    public static final String BEARER = "Bearer ";
    public static final String BASIC = "Basic ";
    public static final int MAX_TOKEN_REQUEST_ATTEMPTS = 2;
    public static final String CALL_CHOREO = "callChoreo";
    public static final String ADDITIONAL_CLAIMS = "additionalClaims";
    public static final String JWT_CLAIMS = "jwtClaims";

}
