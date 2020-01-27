/*
 * SecurityConfiguration$
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
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Timer;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.net.ssl.HostnameVerifier;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.processor.HTTPArtifactBinding;
import org.springframework.security.saml.processor.HTTPPAOS11Binding;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.HTTPSOAP11Binding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.trust.httpclient.TLSProtocolSocketFactory;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity(debug = true)
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)

public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Value("${security.saml2.metadata-url}")
	String metadataUrl = "https://dev-856753.oktapreview.com/app/exkoxna6axOLKemok0h7/sso/saml/metadata";

	private Timer backgroundTaskTimer;
	private MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager;

	@Autowired
	private SAMLUserDetailsServiceImpl samlUserDetailsServiceImpl;

	@PostConstruct
	public void init() {
		this.backgroundTaskTimer = new Timer(true);
		this.multiThreadedHttpConnectionManager = new MultiThreadedHttpConnectionManager();
		final Properties props = System.getProperties();
		props.setProperty("jdk.internal.httpclient.disableHostnameVerification", Boolean.TRUE.toString());
		props.setProperty("javax.net.ssl.HostnameVerifier", Boolean.FALSE.toString());

	}
	
	@PreDestroy
	public void destroy() {
		this.backgroundTaskTimer.purge();
		this.backgroundTaskTimer.cancel();
		this.multiThreadedHttpConnectionManager.shutdown();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.httpBasic().authenticationEntryPoint(samlEntryPoint());
		http.csrf().disable();
		http.addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class).addFilterAfter(samlFilter(),
				BasicAuthenticationFilter.class);
		http.authorizeRequests().antMatchers("/").permitAll().antMatchers("/error").permitAll().antMatchers("/saml/**")
				.permitAll().anyRequest().authenticated();
		http.logout().logoutSuccessUrl("/");
	}

	@Bean
	public FilterChainProxy samlFilter() throws Exception {
		List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>();
		
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"), samlEntryPoint()));
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"), samlLogoutFilter()));
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
				metadataDisplayFilter()));
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
				samlWebSSOProcessingFilter()));
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSOHoK/**"),
				samlWebSSOHoKProcessingFilter()));
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"),
				samlLogoutProcessingFilter()));
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"), samlIDPDiscovery()));
		
		return new FilterChainProxy(chains);
	}

	/**
	 * SAML discovery filter. This filter redirects/forwards to the idp selction page internally.
	 * @return
	 */
	@Bean
	public SAMLDiscovery samlIDPDiscovery() {
		SAMLDiscovery idpDiscovery = new SAMLDiscovery();
		
		/**
		 * Local discovery service: The selection page can be customized using property idpSelectionPath on bean samlIDPDiscovery.
		 * System forwards to this page with a discovery request which includes the following request attributes:

				idpDiscoReturnURL - URL to send the IDP selection result to using GET action

				idpDiscoReturnParam - name of the GET parameter to include the entity ID of the selected IDP
		 */
		
		idpDiscovery.setIdpSelectionPath("/saml/idpSelection");
		
		return idpDiscovery;
	}

	
	
	/**
	 * Filter for SAML metadata endpoint
	 */
	@Bean
	public MetadataDisplayFilter metadataDisplayFilter() {
		return new MetadataDisplayFilter();
	}
	
	/**
	 * Global Logout filter. This bean is not used in case of local logout.
	 * @return
	 */
	@Bean
	public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
		return new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
	}

	/**
	 * Intercepts local logout call. Makes use of samlLogoutFilter and logoutHandler beans.
	 * Overrides default logout processing filter with the one processing SAML messages
	 */
	 
	@Bean
	public SAMLLogoutFilter samlLogoutFilter() {
		return new SAMLLogoutFilter(successLogoutHandler(), new LogoutHandler[] { logoutHandler() },
				new LogoutHandler[] { logoutHandler() });
	}

	/**
	 * Invoked on successful logout
	 * @return
	 */
	@Bean
	public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
		SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
		/**
		 * Redirect URL after successful logout
		 */
		successLogoutHandler.setDefaultTargetUrl("/");
		return successLogoutHandler;
	}

	/**
	 *  Logout handler terminating local session and removing Authentication object
	 */
	@Bean
	public SecurityContextLogoutHandler logoutHandler() {
		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.setInvalidateHttpSession(true);
		logoutHandler.setClearAuthentication(true);
		return logoutHandler;
	}
	
	

	/**
	 * The filter expects calls on configured URL and presents user with SAML2 metadata representing
	 * this application deployment. In case the application is configured to automatically generate metadata,
	 * the generation occurs upon first invocation of this filter (first request made to the server).
	 * 
	 * 
	 * This filter is automatically invoked as part of the first request to a URL processed by Spring Security. 
	 * In case there is no service provider metadata already specified (meaning property hostedSPName of the metadata bean is empty) filter will generate a new one.
	 *
	 */

	@Bean
	public MetadataGeneratorFilter metadataGeneratorFilter() {
		return new MetadataGeneratorFilter(metadataGenerator());
	}

	@Bean
	public MetadataGenerator metadataGenerator() {
		MetadataGenerator metadataGenerator = new MetadataGenerator();
		// metadataGenerator.setEntityId("com:fengxin58:spring:sp");
		metadataGenerator.setEntityId("https://localhost:8443/saml/metadata");
		metadataGenerator.setExtendedMetadata(extendedMetadata());
		
		//Enables local discovery service
		metadataGenerator.setIncludeDiscoveryExtension(true);
		
		metadataGenerator.setKeyManager(keyManager());
		return metadataGenerator;
	}

	@Bean
	public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {
		SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter = new SAMLWebSSOHoKProcessingFilter();
		samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
		samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager());
		samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
		return samlWebSSOHoKProcessingFilter;
	}

	
	/**
	 * Errors produced during processing of the SAML AuthenticationResponse can be handled by plugging a custom implementation 
	 * of the org.springframework.security.web.authentication.AuthenticationFailureHandler interface to the samlWebSSOProcessingFilter bean
	 * @return
	 * @throws Exception
	 */
	@Bean
	public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
		SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
		samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
		samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
		samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
		return samlWebSSOProcessingFilter;
	}

	@Bean
	public SAMLAuthenticationSuccessHandler successRedirectHandler() {
		SAMLAuthenticationSuccessHandler successRedirectHandler = successHandler();
		successHandler().setDefaultTargetUrl("/landing");
		return successRedirectHandler;
	}

	
	/**
	 * Successful authentication using SAML token results in creation of an Authentication object by the SAMLAuthenticationProvider. 
	 * By default instance of org.springframework.security.providers.ExpiringUsernameAuthenticationToken is created. 
	 * Content of the resulting object can be customized by setting properties of the samlAuthenticationProvider bean
	 * @return
	 */
	@Bean
	public SAMLAuthenticationProvider samlAuthenticationProvider() {
		SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
		samlAuthenticationProvider.setUserDetails(samlUserDetailsServiceImpl);
		samlAuthenticationProvider.setForcePrincipalAsString(false);
		return samlAuthenticationProvider;
	}

	 /**
	  * Class is able to process Response objects returned from the IDP after SP initialized SSO or unsolicited
	  * response from IDP. In case the response is correctly validated and no errors are found the SAMLCredential
	  * is created.
	  *
	  */
	@Bean
	public WebSSOProfileConsumer webSSOprofileConsumer() {
		WebSSOProfileConsumerImpl webSSOProfileConsumer = new WebSSOProfileConsumerImpl();
		
		/**
		 * Assertion used to authenticate user is stored in the SAMLCredential object under property authenticationAssertion.
		 *  By default the original content (DOM) of the assertion is discarded and system only keeps an unmarshalled version which might slightly differ from the original, e.g. in white-spaces. 
		 * In order to instruct Spring SAML to keep the assertion in the original form (keep its DOM) set property releaseDOM to false on bean WebSSOProfileConsumerImpl.
		 * 
		 * To get the Assertion XML as String,
		 * XMLHelper.nodeToString(SAMLUtil.marshallMessage(credential.getAuthenticationAssertion()))
		 */
		webSSOProfileConsumer.setReleaseDOM(false);
		
		return webSSOProfileConsumer;
	}

	// SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
	@Bean
	public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
		return new WebSSOProfileConsumerHoKImpl();
	}

	@Bean
	public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
		SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
		failureHandler.setUseForward(true);
		failureHandler.setDefaultFailureUrl("/error");
		return failureHandler;
	}

	@Bean
	public SAMLProcessorImpl processor() {
		Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>();
		bindings.add(httpRedirectDeflateBinding());
		bindings.add(httpPostBinding());
		bindings.add(artifactBinding(parserPool(), velocityEngine()));
		bindings.add(httpSOAP11Binding());
		bindings.add(httpPAOS11Binding());
		return new SAMLProcessorImpl(bindings);

	}

	// Bindings
	private ArtifactResolutionProfile artifactResolutionProfile() {
		final ArtifactResolutionProfileImpl artifactResolutionProfile = new ArtifactResolutionProfileImpl(httpClient());
		artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()));
		return artifactResolutionProfile;
	}

	@Bean
	public HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
		return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile());
	}

	@Bean
	public VelocityEngine velocityEngine() {
		return VelocityFactory.getEngine();
	}

	@Bean
	public HTTPSOAP11Binding soapBinding() {
		return new HTTPSOAP11Binding(parserPool());
	}

	@Bean
	public HTTPPostBinding httpPostBinding() {
		return new HTTPPostBinding(parserPool(), velocityEngine());
	}

	@Bean
	public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
		return new HTTPRedirectDeflateBinding(parserPool());
	}

	@Bean
	public HTTPSOAP11Binding httpSOAP11Binding() {
		return new HTTPSOAP11Binding(parserPool());
	}

	@Bean
	public HTTPPAOS11Binding httpPAOS11Binding() {
		return new HTTPPAOS11Binding(parserPool());
	}

	/**
	 * SP initialized SSO process can be started in two ways:
		User accesses a resource protected by Spring Security which initializes SAMLEntryPoint	
	 * Dependent Beans: webSSOProfile, samlLogger
	 * 
	 * @param webSSOProfileOptions
	 * @return
	 */
	@Bean
	public SAMLEntryPoint samlEntryPoint() {
		SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
		samlEntryPoint.setDefaultProfileOptions(webSSOProfileOptions());
		return samlEntryPoint;
	}

	@Bean
	public SAMLContextProviderImpl contextProvider() {
		return new SAMLContextProviderImpl();
	}
	
	/**
	 * After identification of IDP to use for authentication (for details see Section 9.1, “IDP selection and discovery”), 
	 * SAML Extension creates an AuthnRequest SAML message and sends it to the selected IDP. 
	 * Both construction of the AuthnRequest and binding used to send it can be customized using WebSSOProfileOptions object.
	 * @return
	 */

	@Bean
	public WebSSOProfileOptions webSSOProfileOptions() {
		WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
		webSSOProfileOptions.setIncludeScoping(false);
		webSSOProfileOptions.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		/**
		 * Sets Relay State
		 */
		webSSOProfileOptions.setRelayState("Relay123");
		return webSSOProfileOptions;
	}

	@Bean
	public SAMLAuthenticationSuccessHandler successHandler() {
		return new SAMLAuthenticationSuccessHandler();
	}

	/**
	 * Logger for SAML messages and events
	 * 
	 * @return
	 */
	@Bean
	public SAMLDefaultLogger samlLogger() {
		SAMLDefaultLogger logger = new SAMLDefaultLogger();
		logger.setLogAllMessages(true);
		return logger;
	}

	/**
	 * Profile for consumption of processed messages. Required by SAMLEntryPoint
	 * Dependent Beans: MetadataManager
	 */
	@Bean
	public WebSSOProfile webSSOprofile() {
		return new WebSSOProfileImpl();
	}

	@Bean
	@Qualifier("metadata")
	public CachingMetadataManager metadata() throws MetadataProviderException {
		List<MetadataProvider> providers = new ArrayList<MetadataProvider>();
		providers.add(oktaCircleExtendedMetadataProvider());
		CachingMetadataManager cachingMetadataManager = new CachingMetadataManager(providers);
		
		//cachingMetadataManager.setDefaultIDP("");
			
		return cachingMetadataManager;
	}

	@Bean
	public KeyManager keyManager() {

		
		/*
		 * DefaultResourceLoader loader = new DefaultResourceLoader();
		 * org.springframework.core.io.Resource storeFile =
		 * loader.getResource("classpath:saml/keystore.jks"); String storePass =
		 * "changeit";
		 * 
		 * 
		 * Map<String, String> passwords = new HashMap<String, String>();
		 * passwords.put("pega", "changeit");
		 * 
		 * 
		 * String defaultKey = "pega"; return new JKSKeyManager(storeFile, storePass,
		 * passwords, defaultKey);
		 */
		 

		
		  DefaultResourceLoader loader = new DefaultResourceLoader();
		  org.springframework.core.io.Resource storeFile =
		  loader.getResource("classpath:/saml/samlKeystore.jks"); String storePass =
		  "nalle123"; Map<String, String> passwords = new HashMap<String, String>();
		  passwords.put("apollo", "nalle123"); String defaultKey = "apollo"; return new
		  JKSKeyManager(storeFile, storePass, passwords, defaultKey);
		 

	}

	/**
	 * Returns instance of HttpMetadataProvider
	 * @return
	 * @throws MetadataProviderException
	 */
	@Bean
	@Qualifier("idp-okta")
	public ExtendedMetadataDelegate oktaCircleExtendedMetadataProvider() throws MetadataProviderException {

		final Properties props = System.getProperties();
		props.setProperty("jdk.internal.httpclient.disableHostnameVerification", Boolean.TRUE.toString());

		// Pulls the metadata using the provided httpClient
		HTTPMetadataProvider httpoktaMetadataProvider = new HTTPMetadataProvider(this.backgroundTaskTimer, httpClient(),
				this.metadataUrl);

		httpoktaMetadataProvider.setParserPool(parserPool());

		ExtendedMetadataDelegate extendedoktaMetadataDelegate = new ExtendedMetadataDelegate(httpoktaMetadataProvider,
				extendedMetadata());
		
		//Disable signature verification
		extendedoktaMetadataDelegate.setMetadataTrustCheck(false);
		
		//Aliases of all the trusted keys to be used during signature verification of the Idp metadata
		extendedoktaMetadataDelegate.setMetadataTrustedKeys(null);
		
		//Only accepts signed metadata if set True
		extendedoktaMetadataDelegate.setMetadataRequireSignature(false);
		backgroundTaskTimer.purge();
		return extendedoktaMetadataDelegate;
	}

	@Bean
	public HttpClient httpClient() {
		HttpClient httpClient = new HttpClient(this.multiThreadedHttpConnectionManager);
		return httpClient;
	}

	/**
	 * XML parser pool needed for OpenSAML parsing
	 * 
	 * @return
	 */
	@Bean(initMethod = "initialize")
	public StaticBasicParserPool parserPool() {
		return new StaticBasicParserPool();
	}

	/**
	 * Each metadata document can contain definition for one or many identity or service providers and optionally can be digitally signed. 
	 * Metadata can be customized either by direct modifications to the XML document, or using extended metadata. 
	 * Extended metadata is added directly to the Spring configuration file and can contain additional options which are unavailable in the basic metadata document.
	 * 
	 * @return
	 */
	@Bean
	public ExtendedMetadata extendedMetadata() {
		ExtendedMetadata extendedMetadata = new ExtendedMetadata();
		extendedMetadata.setIdpDiscoveryEnabled(true);
		extendedMetadata.setSignMetadata(false);
		extendedMetadata.setEcpEnabled(true);
		extendedMetadata.setAlias("OKTA");
		
		/**
		 While MetaIOP needs to have the exact version of the certificate which will be used for signatures, 
		 PKIX uses verification based on trusted certification authorities (just like e.g. web browsers do) - 
		 which means you don't need to have the exact certificate used for signature in advance - 
		 as long as it's issued by one of the CAs you trust. 
		 PKIX also verifies e.g. certificate validity period 
		 (and other checks in certification path validation of RFC 5280 - https://en.wikipedia.org/wiki/Certification_path_validation_algorithm)
		 */
		extendedMetadata.setSecurityProfile("pkix");
		
		/**
		Sets hostname verifier to use for verification of SSL connections. The following values are available: 

		default: org.apache.commons.ssl.HostnameVerifier.DEFAULT 
		defaultAndLocalhost: org.apache.commons.ssl.HostnameVerifier.DEFAULT_AND_LOCALHOST 
		strict: org.apache.commons.ssl.HostnameVerifier.STRICT 
		allowAll: org.apache.commons.ssl.HostnameVerifier.ALLOW_ALL, doesn't perform any validation

		 */
		extendedMetadata.setSslHostnameVerification("strict");
		
		return extendedMetadata;
	}

	@Bean
	public TLSProtocolConfigurer tlsProtocolConfigurer() {
		TLSProtocolConfigurer configurer = new TLSProtocolConfigurer();
		configurer.setSslHostnameVerification("allowAll");
		return configurer;
	}

	@Bean
	public ProtocolSocketFactory socketFactory() {

		return new TLSProtocolSocketFactory(keyManager(), null, "allowAll");
	}

	@Bean
	public Protocol socketFactoryProtocol() {
		return new Protocol("https", socketFactory(), 443);
	}
	
	@Bean
	public MethodInvokingFactoryBean socketFactoryInitialization() {
		MethodInvokingFactoryBean methodInvokingFactoryBean = new MethodInvokingFactoryBean();
		methodInvokingFactoryBean.setTargetClass(Protocol.class);
		methodInvokingFactoryBean.setTargetMethod("registerProtocol");
		Object[] args = { "https", socketFactoryProtocol() };
		methodInvokingFactoryBean.setArguments(args);

		return methodInvokingFactoryBean;
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	/**
	 * Sets a custom authentication provider.
	 * 
	 * @param auth SecurityBuilder used to create an AuthenticationManager.
	 * @throws Exception
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(samlAuthenticationProvider());
	}



	// Initialization of OpenSAML library
	@Bean
	public static SAMLBootstrap sAMLBootstrap() {
		return new SAMLBootstrap();
	}

	@Bean
	public SingleLogoutProfile logoutprofile() {
		return new SingleLogoutProfileImpl();
	}

}