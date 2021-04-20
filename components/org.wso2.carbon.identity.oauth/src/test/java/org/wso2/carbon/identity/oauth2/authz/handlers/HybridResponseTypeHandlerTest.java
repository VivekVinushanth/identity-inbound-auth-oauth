/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.authz.handlers;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.TestConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AuthorizeRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AuthzCodeDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2TokenUtil;

import static org.powermock.api.mockito.PowerMockito.*;

/**
 * Test class covering HybridResponseTypeHandler
 */

@WithCarbonHome
@WithH2Database(files = {"dbScripts/h2.sql", "dbScripts/identity.sql"})
@WithRealmService(tenantId = TestConstants.TENANT_ID,
        tenantDomain = TestConstants.TENANT_DOMAIN,
        initUserStoreManager = true,
        injectToSingletons = {OAuthComponentServiceHolder.class})
@PrepareForTest({OAuth2TokenUtil.class})

public class HybridResponseTypeHandlerTest {


    private static final String TEST_CONSUMER_KEY = "testconsumenrkey";
    private static final String TEST_CALLBACK_URL = "https://localhost:8000/callback";

    OAuthAuthzReqMessageContext authAuthzReqMessageContext;
    OAuth2AuthorizeReqDTO authorizationReqDTO;

    @BeforeMethod
    public void setUp() throws Exception {

        authorizationReqDTO = new OAuth2AuthorizeReqDTO();
        authorizationReqDTO.setCallbackUrl(TEST_CALLBACK_URL);
        authorizationReqDTO.setConsumerKey(TEST_CONSUMER_KEY);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("testUser");
        authenticatedUser.setTenantDomain("carbon.super");
        authenticatedUser.setUserStoreDomain("PRIMARY");
        authorizationReqDTO.setUser(authenticatedUser);
        authorizationReqDTO.setResponseType(OAuthConstants.GrantTypes.TOKEN);
    }

    @AfterMethod
    public void tearDown() throws Exception {
    }

    /**
     * This data provider is added to enable affected test cases to be tested in both
     * where the IDP_ID column is available and not available in the relevant tables.
     */
    @DataProvider(name = "IdpIDColumnAvailabilityDataProvider")
    public Object[][] idpIDColumnAvailabilityDataProvider() {
        return new Object[][]{
                {true},
                {false}
        };
    }

    @Test(dataProvider = "IdpIDColumnAvailabilityDataProvider")
    public void testIssue(boolean isIDPIdColumnEnabled) throws Exception {

        OAuth2ServiceComponentHolder.setIDPIdColumnEnabled(isIDPIdColumnEnabled);
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setGrantTypes("implicit");
        oAuthAppDO.setOauthConsumerKey(TEST_CONSUMER_KEY);
        oAuthAppDO.setState("active");
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserStoreDomain("PRIMARY");
        user.setUserName("testUser");
        user.setFederatedIdPName(TestConstants.LOCAL_IDP);

        oAuthAppDO.setUser(user);
        oAuthAppDO.setApplicationName("testApp");

        AppInfoCache appInfoCache = AppInfoCache.getInstance();
        appInfoCache.addToCache(TEST_CONSUMER_KEY, oAuthAppDO);

        HybridResponseTypeHandler hybridResponseTypeHandler = new HybridResponseTypeHandler();
        hybridResponseTypeHandler.init();


        authorizationReqDTO.setResponseType(OAuthConstants.GrantTypes.AUTHORIZATION_CODE);
        authAuthzReqMessageContext
                = new OAuthAuthzReqMessageContext(authorizationReqDTO);
        authAuthzReqMessageContext
                .setApprovedScope(new String[]{"scope1", "scope2", OAuthConstants.Scope.OPENID});

        OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO =
                hybridResponseTypeHandler.issue(authAuthzReqMessageContext);

        // Validating whether authorization code and response for authorization code flow is generated.
        Assert.assertNotNull(oAuth2AuthorizeRespDTO.getAuthorizationCode(), "Authorization code obtained when " +
                "response type is CODE");

    }

//    @Test(dataProvider = "IdpIDColumnAvailabilityDataProvider")
//    public void testIssue1(boolean isIDPIdColumnEnabled) throws Exception {
//
//        OAuth2ServiceComponentHolder.setIDPIdColumnEnabled(isIDPIdColumnEnabled);
//        OAuthAppDO oAuthAppDO = new OAuthAppDO();
//        oAuthAppDO.setGrantTypes("implicit");
//        oAuthAppDO.setOauthConsumerKey(TEST_CONSUMER_KEY);
//        oAuthAppDO.setState("active");
//        AuthenticatedUser user = new AuthenticatedUser();
//        user.setUserStoreDomain("PRIMARY");
//        user.setUserName("testUser");
//        user.setFederatedIdPName(TestConstants.LOCAL_IDP);
//
//        oAuthAppDO.setUser(user);
//        oAuthAppDO.setApplicationName("testApp");
//
//        AppInfoCache appInfoCache = AppInfoCache.getInstance();
//        appInfoCache.addToCache(TEST_CONSUMER_KEY, oAuthAppDO);
//
//        HybridResponseTypeHandler hybridResponseTypeHandler = new HybridResponseTypeHandler();
//        hybridResponseTypeHandler.init();
//
//        authorizationReqDTO.setResponseType(OAuthConstants.GrantTypes.TOKEN);
//        authAuthzReqMessageContext
//                = new OAuthAuthzReqMessageContext(authorizationReqDTO);
//        authAuthzReqMessageContext
//                .setApprovedScope(new String[]{"scope1", "scope2", OAuthConstants.Scope.OPENID});
//
//        mockStatic(OAuth2TokenUtil.class);
//        doNothing().when(OAuth2TokenUtil.class);
//
//        OAuth2AuthorizeRespDTO oAuth2AuthorizeRespDTO =
//                hybridResponseTypeHandler.issue(authAuthzReqMessageContext);
//
//        Assert.assertNotNull(oAuth2AuthorizeRespDTO.getAuthorizationCode(), "Authorization code obtained when " +
//                "response type is CODE");
//    }
}
