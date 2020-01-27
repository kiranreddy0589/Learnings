/*
 * IndexController$
 *
 * Copyright (c) 2019  Pegasystems Inc.
 * All rights reserved.
 *
 * This  software  has  been  provided pursuant  to  a  License
 * Agreement  containing  restrictions on  its  use.   The  software
 * contains  valuable  trade secrets and proprietary information  of
 * Pegasystems Inc and is protected by  federal   copyright law.  It
 * may  not be copied,  modified,  translated or distributed in  any
 * form or medium,  disclosed to third parties or used in any manner
 * not provided for in  said  License Agreement except with  written
 * authorization from Pegasystems Inc.
 */
package com.example.demo;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class IndexController {
    
    

   @RequestMapping("/helloworld")
   public Map<String, Object> getSAMLAssertionData() {
	   Map<String, Object> assertionData = new LinkedHashMap<String, Object>();
	   Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
       SAMLCredential credential = (SAMLCredential) authentication.getCredentials();
       Assertion assertion = credential.getAuthenticationAssertion();
       
       assertionData.put("NameID", credential.getNameID().getValue());
       assertionData.put("RelayState", credential.getRelayState());
       assertionData.put("LocalEntityID", credential.getLocalEntityID());
       assertionData.put("Issuer", assertion.getIssuer().getValue());
       
       
       System.out.println("NameID: "+ credential.getNameID().getValue());
       System.out.println("RelayState: "+ credential.getRelayState());
       
       System.out.println("LocalEntityID:  "+ credential.getLocalEntityID());
       System.out.println("Issue: "+ assertion.getIssuer().getValue());
       for(AudienceRestriction condition : assertion.getConditions().getAudienceRestrictions()) {
    	   for(Audience audience : condition.getAudiences()) {
    		   assertionData.put("Audience", audience.getAudienceURI());
    	   }
       }
       for(AuthnStatement authStmt : assertion.getAuthnStatements()) {
    	   assertionData.put("AuthStatement:AuthContext:AuthnContextClassRef", authStmt.getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
       }
       List<String> certificates = new ArrayList<String>();
       for(X509Data data : assertion.getSignature().getKeyInfo().getX509Datas()) {
    	   for(X509Certificate certificate : data.getX509Certificates()) {
    		   System.out.println(certificate.getValue());
    		   certificates.add(certificate.getValue());
    		   
    	   }
       }
       assertionData.put("X509Certificates", certificates);
        return assertionData; 

   }
}