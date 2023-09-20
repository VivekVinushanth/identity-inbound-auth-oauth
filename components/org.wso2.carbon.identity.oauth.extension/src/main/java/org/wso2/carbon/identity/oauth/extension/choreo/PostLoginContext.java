package org.wso2.carbon.identity.oauth.extension.choreo;

import com.nimbusds.jwt.JWTClaimsSet;

import java.util.HashMap;
import java.util.Map;

public class PostLoginContext {

    public AccessToken accessToken;
    public IdToken idToken;

    public PostLoginContext(JWTClaimsSet accessTokenClaimset,JWTClaimsSet idTokenClaimset) {
        this.accessToken = new AccessToken(accessTokenClaimset);
        this.idToken = new IdToken(idTokenClaimset);
    }
    public static class AccessToken {
        private static Map<String,String> claims = new HashMap<>();
        public AccessToken(JWTClaimsSet jwtClaimsSet) {
            for (Map.Entry<String, Object> entry : jwtClaimsSet.getClaims().entrySet()) {
                if (entry.getValue() instanceof String) {
                    claims.put(entry.getKey(), (String) entry.getValue());
                }
            }
        }
        public String claim(String key) {
            return claims.get(key);
        }
        public Map<String, String> getAllClaims() {
            return claims;
        }

        public void setAdditionalClaims(String key, String value) {
            claims.put(key,value);
        }
    }
    public static class IdToken {
        private static Map<String,String> claims = new HashMap<>();
        public IdToken(JWTClaimsSet jwtClaimsSet) {
            for (Map.Entry<String, Object> entry : jwtClaimsSet.getClaims().entrySet()) {
                if (entry.getValue() instanceof String) {
                    claims.put(entry.getKey(), (String) entry.getValue());
                }
            }
        }
        public String claim(String key) {
            return claims.get(key);
        }

        public void setAdditionalClaims(String key, String value) {
            claims.put(key,value);
        }
    }
}
