package com.oauth2.security.oauthbearer;

import java.security.interfaces.RSAPublicKey;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.net.URL;
public class Test {
    public static void main(String[] args) {
        try {

            // JwkProvider provider1 = new JwkProviderBuilder("https://samples.auth0.com/").build();
            String accessToken = "...";
            DecodedJWT jwt = JWT.decode(accessToken);
            UrlJwkProvider provider = new UrlJwkProvider(new URL("https://container.googleapis.com/v1/projects/gowish/locations/europe-north1/clusters/gowish-north-1/jwks"));
            
            Jwk jwk = provider.get(jwt.getKeyId());
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
            
            algorithm.verify(jwt);
            System.out.println("ACCESS TOKEN OK"); 
        
        } catch (Exception err){
            
            System.out.println("ERROR: " + err.getMessage()); 
        }
    }
}
