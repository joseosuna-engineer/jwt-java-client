package com.prottonne.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import java.util.LinkedHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtParser {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Value("${token.secret}")
    private String tokenSecret;

    private final String claimName = "object name in jwt token";

    public JwtParser() {
        super();
    }

    public Object parse(String jwtToken) throws JsonProcessingException {

        Jws<Claims> claims
                = Jwts.
                        parser().
                        setSigningKey(tokenSecret).
                        parseClaimsJws(jwtToken);

        String idToken = claims.getBody().getId();

        return getObject(claims.getBody());
    }

    private Object getObject(Claims claims) throws JsonProcessingException {

        LinkedHashMap linkedHashMap
                = (LinkedHashMap) claims.get(claimName);

        ObjectMapper mapper = new ObjectMapper();
        String st = mapper.writeValueAsString(linkedHashMap);

        Object object
                = mapper.readValue(st, new TypeReference<Object>() {
                });

        if (null == object) {
            throw new RuntimeException("no data in token");
        }

        return object;
    }
}
