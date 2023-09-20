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

import com.google.gson.Gson;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsLogger;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.oauth.extension.choreo.CallChoreoFunctionImpl;
import org.wso2.carbon.identity.oauth.extension.choreo.PostLoginContext;
import org.wso2.carbon.identity.oauth.extension.choreo.callback.Callback;
import org.wso2.carbon.identity.oauth.extension.engine.JSEngine;


import javax.script.ScriptException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.oauth.extension.utils.Constants.*;

public class JSEngineUtil {

    private static final org.apache.commons.logging.Log log = LogFactory.getLog(JSEngineUtil.class);

    /**
     * Get the Access Token extended claims based on the adaptive script.
     *
     * @return JWTClaimsSet.
     */
    public static JWTClaimsSet getAccessTokenExtendedClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder, ServiceProvider serviceProvider, String tenantDomain,
                                                            JWTClaimsSet jwtClaimsSet) {

        Map<String,String> additionalClaims = new HashMap<>();
        if (serviceProvider.getLocalAndOutBoundAuthenticationConfig().getAuthenticationScriptConfig() == null) {
            return jwtClaimsSet;
        }
        if (!serviceProvider.getLocalAndOutBoundAuthenticationConfig().
                getAuthenticationScriptConfig().getContent().contains(ADD_TO_ACCESS_TOKEN)) {
            return jwtClaimsSet;
        }

        try {
            Gson gson = new Gson();
            JSEngine jsEngineFromConfig = EngineUtils.getEngineFromConfig();
            Map<String, Object> bindings = new HashMap<>();
            JSEngine jsEngine = jsEngineFromConfig.createEngine();
            Callback callback = EngineUtils.getCallbackBasedOnEngine(jsEngine);
            CallChoreoFunctionImpl callChoreo = new CallChoreoFunctionImpl(tenantDomain, callback);
            JsLogger jsLogger = new JsLogger();
            bindings.put(FrameworkConstants.JSAttributes.JS_LOG, jsLogger);
            bindings.put(CALL_CHOREO, callChoreo);
            List<String> accessTokenExtendedClaims = new ArrayList<>();
            accessTokenExtendedClaims.add("context");
            bindings.put(ADDITIONAL_CLAIMS, additionalClaims);
            bindings.put(JWT_CLAIMS, jwtClaimsSet);
            PostLoginContext postLoginContext = new PostLoginContext(jwtClaimsSet, new JWTClaimsSet.Builder().build());
            bindings.put("context", postLoginContext);

            Map<String, Object> result = jsEngine
                    .addBindings(bindings)
                    .evalScript(
                            serviceProvider.getLocalAndOutBoundAuthenticationConfig().getAuthenticationScriptConfig()
                                    .getContent())
//                    .invokeFunction(ADD_TO_ACCESS_TOKEN,jwtClaimsSet, additionalClaims)
                    .invokeFunction(ADD_TO_ACCESS_TOKEN, postLoginContext)
                    .getJSObjects(accessTokenExtendedClaims);

//            additionalClaims = gson.fromJson(gson.toJson(result.get(ADDITIONAL_CLAIMS)), Map.class);
            PostLoginContext postLoginContext1 = gson.fromJson(gson.toJson(result.get("context")), PostLoginContext.class);
            for (Map.Entry<String, String> entry : postLoginContext1.accessToken.getAllClaims().entrySet()) {
                jwtClaimsSetBuilder.claim(entry.getKey(), entry.getValue());
            }
            return jwtClaimsSetBuilder.build();
        } catch (ScriptException | NoSuchMethodException e) {
            log.warn("Error while fetching additional claims through adaptive script.", e);
        }
        return jwtClaimsSet;
    }

    /**
     * Get the ID Token extended claims based on the adaptive script.
     *
     * @return JWTClaimsSet.
     */
    public static JWTClaimsSet getIDTokenExtendedClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                               ServiceProvider serviceProvider, String tenantDomain,
                                               JWTClaimsSet jwtClaimsSet) {

        Map<String,String> additionalClaims = new HashMap<>();
        if (serviceProvider.getLocalAndOutBoundAuthenticationConfig().getAuthenticationScriptConfig() == null) {
            return jwtClaimsSet;
        }
        if (!serviceProvider.getLocalAndOutBoundAuthenticationConfig().
                getAuthenticationScriptConfig().getContent().contains(ADD_TO_IDTOKEN)) {
            return jwtClaimsSet;
        }

        try {
            Gson gson = new Gson();
            JSEngine jsEngineFromConfig = EngineUtils.getEngineFromConfig();
            Map<String, Object> bindings = new HashMap<>();
            JSEngine jsEngine = jsEngineFromConfig.createEngine();
            Callback callback = EngineUtils.getCallbackBasedOnEngine(jsEngine);
            CallChoreoFunctionImpl callChoreo = new CallChoreoFunctionImpl(tenantDomain, callback);
            JsLogger jsLogger = new JsLogger();
            bindings.put(FrameworkConstants.JSAttributes.JS_LOG, jsLogger);
            bindings.put(CALL_CHOREO, callChoreo);
            List<String> accessTokenExtendedClaims = new ArrayList<>();
            accessTokenExtendedClaims.add("context");
//            accessTokenExtendedClaims.add(ADDITIONAL_CLAIMS);
//            bindings.put(ADDITIONAL_CLAIMS, additionalClaims);
            PostLoginContext postLoginContext = new PostLoginContext(jwtClaimsSet, new JWTClaimsSet.Builder().build());
            bindings.put("context", postLoginContext);
//            bindings.put(JWT_CLAIMS, jwtClaimsSet);

            Map<String, Object> result = jsEngine
                    .addBindings(bindings)
                    .evalScript(
                            serviceProvider.getLocalAndOutBoundAuthenticationConfig().getAuthenticationScriptConfig()
                                    .getContent())
//                    .invokeFunction(ADD_TO_IDTOKEN,jwtClaimsSet, additionalClaims)
                    .invokeFunction(ADD_TO_IDTOKEN,postLoginContext)
                    .getJSObjects(accessTokenExtendedClaims);

            PostLoginContext postLoginContextNew =  gson.fromJson(gson.toJson(result.get("context")), PostLoginContext.class);
//            for (Map.Entry<String, String> entry : additionalClaims.entrySet()) {
//                jwtClaimsSetBuilder.claim(entry.getKey(), entry.getValue());
//            }
            return jwtClaimsSetBuilder.build();
            // TODO: 9/11/23 check if it is empty or null
        } catch (ScriptException | NoSuchMethodException e) {
            log.warn("Error while fetching additional claims through adaptive script.", e);
        }
        return jwtClaimsSet;
    }
}

