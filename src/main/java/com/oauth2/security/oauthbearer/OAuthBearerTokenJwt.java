package com.oauth2.security.oauthbearer;

import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import com.auth0.jwt.interfaces.DecodedJWT;

public class OAuthBearerTokenJwt implements OAuthBearerToken {

    private DecodedJWT jwt;

    public OAuthBearerTokenJwt(DecodedJWT jwt){
        super();
        this.jwt = jwt;
    }

    @Override
    public String value() {
        return this.jwt.getToken();
    }

    @Override
    public Set<String> scope() {
        return this.jwt.getClaims().keySet();
    }

    @Override
    public long lifetimeMs() {
        return  this.jwt.getExpiresAt() != null ? this.jwt.getExpiresAt().getTime() - System.currentTimeMillis(): System.currentTimeMillis() + (1000*60*60*24*365*10);
    }

    @Override
    public String principalName() {
        return this.jwt.getSubject();
    }

    @Override
    public Long startTimeMs() {
        return this.jwt.getNotBefore() != null ? this.jwt.getNotBefore().getTime() : 0;
    }

    @Override
    public String toString() {
        
        return "OAuthBearerTokenJwt{" + this.jwt.toString() + "}";
    }
}