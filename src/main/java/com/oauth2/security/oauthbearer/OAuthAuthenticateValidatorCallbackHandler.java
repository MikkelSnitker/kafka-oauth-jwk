package com.oauth2.security.oauthbearer;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallback;
import org.apache.kafka.common.security.oauthbearer.internals.unsecured.OAuthBearerValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.algorithms.Algorithm;

import java.net.MalformedURLException;
import java.net.URL;


public class OAuthAuthenticateValidatorCallbackHandler implements AuthenticateCallbackHandler {
    private final Logger log = LoggerFactory.getLogger(OAuthAuthenticateValidatorCallbackHandler.class);
    private  UrlJwkProvider provider;
    private Map<String, String> moduleOptions = null;
    private boolean configured = false;
    @Override
    public void configure(Map<String, ?> map, String saslMechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        //https://container.googleapis.com/v1/projects/gowish/locations/europe-north1/clusters/gowish-north-1/jwks

        if (Objects.requireNonNull(jaasConfigEntries).size() != 1 || jaasConfigEntries.get(0) == null)
        throw new IllegalArgumentException(
                String.format("Must supply exactly 1 non-null JAAS mechanism configuration (size was %d)",
                        jaasConfigEntries.size()));
        try {                        
        this.moduleOptions = Collections.unmodifiableMap((Map<String, String>) jaasConfigEntries.get(0).getOptions());
        
        this.provider = new UrlJwkProvider(new URL(this.moduleOptions.get("PROVIDER")));
            


        configured = true;
        } catch(MalformedURLException err){
            throw new IllegalArgumentException( err.getMessage() );
        }
    }

    public boolean isConfigured(){
        return this.configured;
    }

    @Override
    public void close() {
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (!isConfigured())
            throw new IllegalStateException("Callback handler not configured");
        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerValidatorCallback)
                try {
                    OAuthBearerValidatorCallback validationCallback = (OAuthBearerValidatorCallback) callback;
                    handleCallback(validationCallback);
                } catch (KafkaException e) {
                    throw new IOException(e.getMessage(), e);
                }
            else
                throw new UnsupportedCallbackException(callback);
        }
    }

    private void handleCallback(OAuthBearerValidatorCallback callback){
        String accessToken = callback.tokenValue();
        if (accessToken == null)
            throw new IllegalArgumentException("Callback missing required token value");

            try {

                DecodedJWT jwt = JWT.decode(accessToken);
                System.out.println("AUTHENTICATE ACCESSTOKEN: " + accessToken );
                Jwk jwk = this.provider.get(jwt.getKeyId());
                Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
                
                algorithm.verify(jwt);

                callback.token(new OAuthBearerTokenJwt(jwt));
            } catch (Exception err){
                System.out.println("AUTHENTICATE FAILED: " + err.getMessage() );
                
                OAuthBearerValidationResult.newFailure(err.getMessage());
            }

    }

}
