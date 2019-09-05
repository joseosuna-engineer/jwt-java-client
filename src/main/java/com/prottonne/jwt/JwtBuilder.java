package com.prottonne.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.UUID;
import javax.xml.bind.JAXBException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtBuilder {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Value("${token.secret}")
    private String tokenSecret;

    private final String claimName = "object name in jwt token";

    @Value("${token.timeup}")
    private Integer tokenTimeup;

    public JwtBuilder() {
        super();
    }

    public String getAccessToken()
            throws JAXBException {

        LocalDateTime now = LocalDateTime.now();

        ZoneId id = ZoneId.systemDefault();
        ZonedDateTime zdt = ZonedDateTime.of(now, id);
        long timeInMillis = zdt.toInstant().toEpochMilli();

        return Jwts.builder().
                setId(getJwtId()).
                setIssuedAt(new Date(timeInMillis)).
                setExpiration(getExpirationDate(timeInMillis)).
                claim(claimName, getClaim()).
                signWith(SignatureAlgorithm.HS512, tokenSecret).
                compact();

    }

    private String getJwtId() {
        return UUID.randomUUID().toString();
    }

    private Date getExpirationDate(long timeInMillis) {
        return new Date(timeInMillis + tokenTimeup);
    }

    private Object getClaim() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
