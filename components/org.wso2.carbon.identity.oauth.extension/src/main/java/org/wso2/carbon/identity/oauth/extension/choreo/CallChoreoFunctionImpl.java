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

package org.wso2.carbon.identity.oauth.extension.choreo;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.concurrent.FutureCallback;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.oauth.extension.choreo.cache.ChoreoAccessTokenCache;
import org.wso2.carbon.identity.oauth.extension.choreo.callback.Callback;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.wso2.carbon.identity.oauth.extension.utils.Constants.*;

public class CallChoreoFunctionImpl implements CallChoreoFunction {

    private static final String URL_VARIABLE_NAME = "url";
    private static final String CONSUMER_KEY_VARIABLE_NAME = "consumerKey";
    private static final String CONSUMER_KEY_ALIAS_VARIABLE_NAME = "consumerKeyAlias";
    private final List<String> choreoDomains;
    private final ChoreoAccessTokenCache choreoAccessTokenCache;
    private static final Log LOG = LogFactory.getLog(CallChoreoFunctionImpl.class);
//    private final String tenantDomain;
    private final Callback callback;
    private final String tenantDomain;
    public CallChoreoFunctionImpl(String tenantDomain, Callback callback) {
        this.choreoDomains = ConfigProvider.getInstance().getChoreoDomains();
        this.choreoAccessTokenCache = ChoreoAccessTokenCache.getInstance();
        this.tenantDomain =  tenantDomain;
        this.callback = callback;
    }

    @Override
    public void callChoreo(Map<String, String> connectionMetaData, Map<String, Object> payloadData,
                           Map<String, Object> eventHandlers) {

        String epUrl = connectionMetaData.get(URL_VARIABLE_NAME);
        try {
            if (!isValidChoreoDomain(epUrl)) {
                LOG.error("Provided Url does not contain a configured choreo domain. Invalid Url: " + epUrl);
                return;
            }

            AccessTokenRequestHelper accessTokenRequestHelper = new AccessTokenRequestHelper(
                    connectionMetaData, payloadData, eventHandlers);
            String accessToken = choreoAccessTokenCache.getValueFromCache(accessTokenRequestHelper.getConsumerKey(),
                    tenantDomain);
            if (StringUtils.isNotEmpty(accessToken) && !isTokenExpired(accessToken)) {
                LOG.info("Active access token is available in cache.");
                accessTokenRequestHelper.callChoreoEndpoint(accessToken);
            } else {
                LOG.debug("Requesting the access token from Choreo");
                accessToken = requestAccessToken(tenantDomain, accessTokenRequestHelper);
                accessTokenRequestHelper.callChoreoEndpoint(accessToken);
            }
        } catch (IllegalArgumentException e) {
            LOG.error("Invalid endpoint Url: " + epUrl, e);
            callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
        } catch (IOException e) {
            LOG.error("Error while requesting access token from Choreo.", e);
            callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
//        } catch (SecretManagementClientException e) {
//            LOG.debug("Client error while resolving Choreo consumer key or secret.", e);
//            callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
//        } catch (SecretManagementException e) {
//            LOG.error("Error while resolving Choreo consumer key or secret.", e);
//            callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
        } catch (Exception e) {
            LOG.error("Error while invoking callChoreo.", e);
            callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
        }
    }

    /**
     * Performs the access token request using client credentials grant type.
     *
     * @param tenantDomain             The tenant domain which the request belongs to.
     * @param accessTokenRequestHelper The future callback that needs to be called after requesting the token.
     * @return
     * @throws IOException        {@link IOException}
     * @throws FrameworkException {@link FrameworkException}
     */
    private String requestAccessToken(String tenantDomain, AccessTokenRequestHelper accessTokenRequestHelper)
            throws IOException {

        ConfigProvider configProvider = ConfigProvider.getInstance();


        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(configProvider.getConnectionTimeout())
                .setSocketTimeout(configProvider.getReadTimeout())
                .build();
        String tokenEndpoint;
        if (StringUtils.isNotEmpty(accessTokenRequestHelper.getAsgardeoTokenEndpoint())) {
            tokenEndpoint = accessTokenRequestHelper.getAsgardeoTokenEndpoint();
        } else {
            tokenEndpoint = configProvider.getChoreoTokenEndpoint();
        }
        HttpPost request = new HttpPost(tokenEndpoint);
        request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);
        request.setHeader(CONTENT_TYPE, TYPE_FORM_DATA);
        request.setConfig(requestConfig);
        request.setHeader(AUTHORIZATION, BASIC + Base64.getEncoder()
                .encodeToString((accessTokenRequestHelper.consumerKey + ":" + accessTokenRequestHelper.consumerSecret)
                        .getBytes(StandardCharsets.UTF_8)));

        List<BasicNameValuePair> bodyParams = new ArrayList<>();
        bodyParams.add(new BasicNameValuePair(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS));
        request.setEntity(new UrlEncodedFormEntity(bodyParams));
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpResponse response = httpClient.execute(request);
        String responseString = EntityUtils.toString(response.getEntity());
        JsonObject jsonObject = JsonParser.parseString(responseString).getAsJsonObject();
        return jsonObject.get("access_token").toString().replaceAll("\"", "");
    }

    /**
     * This method decodes access token and compare its expiry time with the current time to decide whether it's
     * expired.
     *
     * @param accessToken Access token which needs to be evaluated
     * @return A boolean value indicating whether the token is expired
     * @throws ParseException {@link ParseException}
     */
    private boolean isTokenExpired(String accessToken) throws ParseException {

        SignedJWT decodedToken = SignedJWT.parse(accessToken);
        Date expiryDate = (Date) decodedToken.getJWTClaimsSet().getClaim(JWT_EXP_CLAIM);
        LocalDateTime expiryTimestamp = LocalDateTime.ofInstant(expiryDate.toInstant(), ZoneId.systemDefault());
        return LocalDateTime.now().isAfter(expiryTimestamp);
    }

    private boolean isValidChoreoDomain(String url) {

        if (StringUtils.isBlank(url)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Provided url for domain restriction checking is null or empty.");
            }
            return false;
        }

        if (choreoDomains.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No domains configured for domain restriction. Allowing url by default. Url: " + url);
            }
            return true;
        }

        String domain;
        try {
            domain = getParentDomainFromUrl(url);
        } catch (URISyntaxException e) {
            LOG.error("Error while resolving the domain of the url: " + url, e);
            return false;
        }

        if (StringUtils.isEmpty(domain)) {
            LOG.error("Unable to determine the domain of the url: " + url);
            return false;
        }

        if (choreoDomains.contains(domain)) {
            return true;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Domain: " + domain + " extracted from url: " + url + " is not available in the " +
                    "configured choreo domain list: " + StringUtils.join(choreoDomains, ','));
        }

        return false;
    }

    private String getParentDomainFromUrl(String url) throws URISyntaxException {

        URI uri = new URI(url);
        String parentDomain = null;
        String domain = uri.getHost();
        String[] domainArr;
        if (domain != null) {
            domainArr = StringUtils.split(domain, DOMAIN_SEPARATOR);
            if (domainArr.length != 0) {
                parentDomain = domainArr.length == 1 ? domainArr[0] : domainArr[domainArr.length - 2];
                parentDomain = parentDomain.toLowerCase();
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Parent domain: " + parentDomain + " extracted from url: " + url);
        }
        return parentDomain;
    }

    private class AccessTokenRequestHelper implements FutureCallback<HttpResponse> {

        private final Map<String, String> connectionMetaData;
        private final Map<String, Object> payloadData;
        private final Gson gson;
        private final AtomicInteger tokenRequestAttemptCount;
        private String consumerKey;
        private String consumerSecret;
        private Map<String, Object> eventHandlers;
        private String asgardeoTokenEndpoint;

        public AccessTokenRequestHelper(Map<String, String> connectionMetaData,
                                        Map<String, Object> payloadData, Map<String, Object> eventHandlers) {

            this.connectionMetaData = connectionMetaData;
            this.payloadData = payloadData;
            this.gson = new GsonBuilder().create();
            this.tokenRequestAttemptCount = new AtomicInteger(0);
            this.eventHandlers = eventHandlers;
            resolveConsumerKeySecrete();
        }

        /**
         * The method to be called when access token request receives an HTTP response.
         *
         * @param httpResponse Received HTTP response.
         */
        @Override
        public void completed(HttpResponse httpResponse) {

            boolean isFailure = false;
            try {
                LOG.debug("Access token response received.");
                int responseCode = httpResponse.getStatusLine().getStatusCode();
                if (responseCode == HTTP_STATUS_OK) {
                    Type responseBodyType = new TypeToken<Map<String, String>>() {
                    }.getType();
                    Map<String, String> responseBody = this.gson
                            .fromJson(EntityUtils.toString(httpResponse.getEntity()), responseBodyType);
                    String accessToken = responseBody.get(ACCESS_TOKEN_KEY);
                    LOG.info("Obtained access token from Choreo." + accessToken);
                    if (accessToken != null) {
                        choreoAccessTokenCache.addToCache(this.consumerKey, accessToken, tenantDomain);
                        callChoreoEndpoint(accessToken);
                    } else {
                        LOG.error("Token response does not contain an access token.");
                        isFailure = true;
                    }
                } else {
                    LOG.error("Failed to retrieve access token from Choreo.");
                    isFailure = true;
                }
            } catch (IOException e) {
                LOG.error("Failed to parse access token response to string.", e);
                isFailure = true;
            } catch (Exception e) {
                LOG.error("Error occurred while handling the token response from Choreo.", e);
                isFailure = true;
            }

            if (isFailure) {
                try {
                    return;
//                    asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
                } catch (Exception e) {
                    LOG.error("Error while trying to return after handling the token request failure from Choreo.", e);
                }
            }
        }

        /**
         * The method to be called when access token request fails.
         *
         * @param e Thrown exception.
         */
        @Override
        public void failed(Exception e) {

            LOG.error("Failed to request access token from Choreo", e);
            try {
                String outcome = OUTCOME_FAIL;
                if ((e instanceof SocketTimeoutException) || (e instanceof ConnectTimeoutException)) {
                    outcome = OUTCOME_TIMEOUT;
                }
                callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (Exception ex) {
                LOG.error("Error while proceeding after failing to request access token", e);
            }
        }

        /**
         * The method to be called when access token request canceled.
         */
        @Override
        public void cancelled() {

            LOG.error("Requesting access token from Choreo is cancelled.");
            try {
                callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (Exception e) {
                LOG.error("Error while proceeding after access token request to Choreo got cancelled", e);
            }
        }

        /**
         * Invokes the Choreo API endpoint specified in the connection metadata using the provided access token.
         *
         * @param accessToken Access token that authorizes the request.
         */
        private void callChoreoEndpoint(String accessToken) {

            boolean isFailure = false;
            HttpPost request = new HttpPost(this.connectionMetaData.get(URL_VARIABLE_NAME));
            request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);
            request.setHeader(CONTENT_TYPE, TYPE_APPLICATION_JSON);
            request.setHeader(AUTHORIZATION, BEARER + accessToken);

            try {
                Gson gson = new Gson();
                String payloadJson = gson.toJson(this.payloadData);
                request.setEntity(new StringEntity(payloadJson));
                RequestConfig requestConfig = RequestConfig.custom()
                        .setSocketTimeout(5000)
                        .setConnectTimeout(5000)
                        .build();
                CloseableHttpAsyncClient client = HttpAsyncClients.custom()
                        .setDefaultRequestConfig(requestConfig)
                        .build();
                client.start();
                CountDownLatch latch = new CountDownLatch(1);
                client.execute(request, new FutureCallback<HttpResponse>() {

                    @Override
                    public void completed(final HttpResponse response) {

                        try {
                            handleChoreoEndpointResponse(response);
                        } catch (Exception e) {
                            LOG.error("Error while proceeding after handling the response from Choreo", e);
                        } finally {
                            latch.countDown();
                        }
                    }

                    @Override
                    public void failed(final Exception ex) {

                        LOG.error("Failed to invoke Choreo", ex);
                        try {
                            String outcome = OUTCOME_FAIL;
                            if ((ex instanceof SocketTimeoutException) || (ex instanceof ConnectTimeoutException)) {
                                outcome = OUTCOME_TIMEOUT;
                            }
                            callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
                        } catch (Exception e) {
                            LOG.error("Error while proceeding after failed response from Choreo " +
                                    "call for session data key: ", e);
                        } finally {
                            latch.countDown();
                        }
                    }

                    @Override
                    public void cancelled() {

                        LOG.error("Invocation Choreo for session data key: is cancelled.");
                        try {
                            callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
                        } catch (Exception e) {
                            LOG.error("Error while proceeding after cancelled response from Choreo call for session " +
                                    "data key: ", e);
                        } finally {
                            latch.countDown();
                        }
                    }
                });
                latch.await();
            } catch (UnsupportedEncodingException e) {
                LOG.error("Error while constructing request payload for calling choreo endpoint. session data key: ", e);
                isFailure = true;
            } catch (Exception e) {
                LOG.error("Error while calling Choreo endpoint. session data key: ", e);
                isFailure = true;
            }

            if (isFailure) {
                try {
                    callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
                } catch (Exception e) {
                    LOG.error("Error while trying to return from Choreo call after an exception", e);
                }
            }
        }

        /**
         * Handles the response from the API call to the Choreo endpoint specified in the connection metadata.
         *
         * @param response HTTP response from the Choreo endpoint.
         * @throws FrameworkException {@link FrameworkException}
         */
        private void handleChoreoEndpointResponse(final HttpResponse response) throws FrameworkException {

            Type responseBodyType;
            try {
                int statusCode = response.getStatusLine().getStatusCode();
                Map<String, Object> successResponseBody;
                if (statusCode >= 200 && statusCode < 300) { // Accepting 2xx as success.
                    responseBodyType = new TypeToken<Map<String, Object>>() {
                    }.getType();
                    String responseBodyString = EntityUtils.toString(response.getEntity());
                    if (StringUtils.isEmpty(responseBodyString)) {
                        // To handle the case where the response body is empty.
                        successResponseBody = Collections.emptyMap();
                    } else {
                        successResponseBody = this.gson.fromJson(responseBodyString, responseBodyType);
                    }
                    callback.accept(eventHandlers, successResponseBody, OUTCOME_SUCCESS);
                } else if (statusCode == HTTP_STATUS_UNAUTHORIZED) {
                    responseBodyType = new TypeToken<Map<String, String>>() {
                    }.getType();
                    Map<String, String> responseBody = this.gson
                            .fromJson(EntityUtils.toString(response.getEntity()), responseBodyType);

                    if (ERROR_CODE_ACCESS_TOKEN_INACTIVE.equals(responseBody.get(CODE))) {
                        handleExpiredToken();
                    } else {
                        LOG.warn("Received 401 response from Choreo. Session data key: ");
                        callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
                    }
                } else {
                    LOG.warn("Received non 200 response code from Choreo. Status Code: " + statusCode);
                    callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
                }
            } catch (IOException e) {
                LOG.error("Error while reading response from Choreo call for session data key: ", e);
                callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (Exception e) {
                LOG.error("Error while processing response from Choreo call for session data key: ", e);
                callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
            }
        }

        /**
         * Handles the scenario where the response from the Choreo API call is 401 Unauthorized due to an expired
         * token. The program will retry the token request flow until it exceeds the specified max request attempt
         * count.
         *
         * @throws IOException {@link IOException}
         */
        private void handleExpiredToken() throws IOException {

            if (tokenRequestAttemptCount.get() < MAX_TOKEN_REQUEST_ATTEMPTS) {
                requestAccessToken(tenantDomain, this);
                tokenRequestAttemptCount.incrementAndGet();
            } else {
                LOG.warn("Maximum token request attempt count exceeded for session data key: ");
                tokenRequestAttemptCount.set(0);
                callback.accept(eventHandlers, Collections.emptyMap(), OUTCOME_FAIL);
            }
        }

        public void resolveConsumerKeySecrete() {

            this.consumerKey = connectionMetaData.get(CONSUMER_KEY_VARIABLE_NAME);
            this.consumerSecret = connectionMetaData.get(CONSUMER_SECRET_VARIABLE_NAME);
//            if (StringUtils.isNotEmpty(connectionMetaData.get(CONSUMER_KEY_VARIABLE_NAME))) {
//                this.consumerKey = connectionMetaData.get(CONSUMER_KEY_VARIABLE_NAME);
//            } else {
//                String consumerKeyAlias = connectionMetaData.get(CONSUMER_KEY_ALIAS_VARIABLE_NAME);
//                this.consumerKey = org.wso2.carbon.identity.conditional.auth.functions.choreo.CallChoreoFunctionImpl.getResolvedSecret(consumerKeyAlias);
//            }
//
//            if (StringUtils.isNotEmpty(connectionMetaData.get(CONSUMER_SECRET_VARIABLE_NAME))) {
//                this.consumerSecret = connectionMetaData.get(CONSUMER_SECRET_VARIABLE_NAME);
//            } else {
//                String consumerSecretAlias = connectionMetaData.get(CONSUMER_SECRET_ALIAS_VARIABLE_NAME);
//                this.consumerSecret = CallChoreoFunctionImpl.getResolvedSecret(consumerSecretAlias);
//            }
            if (StringUtils.isNotEmpty(connectionMetaData.get(ASGARDEO_TOKEN_ENDPOINT))) {
                this.asgardeoTokenEndpoint = connectionMetaData.get(ASGARDEO_TOKEN_ENDPOINT);
            }
        }

        public void setConsumerKey(String consumerKey) {

            this.consumerKey = consumerKey;
        }

        public String getConsumerKey() {

            return consumerKey;
        }

        public String getConsumerSecret() {

            return consumerSecret;
        }

        public void setConsumerSecret(String consumerSecret) {

            this.consumerSecret = consumerSecret;
        }

        public String getAsgardeoTokenEndpoint() {

            return asgardeoTokenEndpoint;
        }
    }
}