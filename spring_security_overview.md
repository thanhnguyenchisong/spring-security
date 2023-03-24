# Overview
Framework provides authentication, authorization and  protection against common attracks, support for securing both imperative and reactive applications.
**SpringSecurity source code**: github.com/spring-projects/spring-security/
**Spring Security is Open Source software** released under the Apache 2.0 license.
**Prerequisites**: >= Java8

# Latest version Spring Security 6.0
Requires JDK-17
https://docs.spring.io/spring-security/reference/whats-new.html

### Migration to 6.0
- Upfate to Spring Security 6.0
- Upfate `javax` to `jakarta`
- ....

Care about it after

# Getting Spring Securiy (Quited easy)
### Maven
#### Spring Boot with Maven
```xml
<dependencies>
	<!-- ... other dependency elements ... -->
	<dependency>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-security</artifactId>
	</dependency>
</dependencies>
```
If would like to use `LDAP`, `OAuth 2` and others, need to include more modules and dependencies.
#### Maven without Spring Boot
```xml
<dependencyManagement>
	<dependencies>
		<!-- ... other dependency elements ... -->
		<dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-bom</artifactId>
			<version>{spring-security-version}</version>
			<type>pom</type>
			<scope>import</scope>
		</dependency>
	</dependencies>
</dependencyManagement>
```
or
```xml
<dependencies>
	<!-- ... other dependency elements ... -->
	<dependency>
		<groupId>org.springframework.security</groupId>
		<artifactId>spring-security-web</artifactId>
	</dependency>
	<dependency>
		<groupId>org.springframework.security</groupId>
		<artifactId>spring-security-config</artifactId>
	</dependency>
</dependencies>
```
#### Maven Repositories
All GA release are deployed to Maven Central, so no need more the config in maven repository.

If you use SNAPSHOT version
```xml
<repositories>
	<!-- ... possibly other repository elements ... -->
	<repository>
		<id>spring-snapshot</id>
		<name>Spring Snapshot Repository</name>
		<url>https://repo.spring.io/snapshot</url>
	</repository>
</repositories>
```
If you use milestone or release candidate version
```xml
<repositories>
	<!-- ... possibly other repository elements ... -->
	<repository>
		<id>spring-milestone</id>
		<name>Spring Milestone Repository</name>
		<url>https://repo.spring.io/milestone</url>
	</repository>
</repositories>
```

# Features
### Authentication
comprehensive support for authentication

Authentication is how how we verify the indentity of a user.
Common way is user to enter username and password.

**Password Storage**: 
`PasswordEncoder` interface is used to perform a one way transformation of a password to let the psasword be stored securely, used for storing a password that needs to be compared to a user provided password at the time of authentication.

**Password Storage History**:

1Store by paintext -> data can be dump by SQL injection -> lost the password 

2Store by SHA-256 (Can't be dump data) -> Hacker have `Rainbow Tables` to less the export to get the password then use the hash password in Rainbow Tables to request to our login -> 3Store by a salt + password then generate SHA-256 -> Now computer can generate SHA-256 a bilion per second so they can test with a bilion times in our application via login API. 

=> Less the performance of computer by “work factor” for their own system, A time to authentication take a second at least. So the hacker can't execute many times in a second. Just a time in a second for a thread -> reduce the risk.

**DelegatingPasswordEncoder**

To deal with three real problems.
- Many application use the old password encoding that cann't easily migrate
- The best practice for password storage will change again
- As a framework, Spring Security cann't make breaking changes frequently

By
- Ensuring that passwords are encoded by using the current password storage recommendations.
- Allowing for validating passwords in modern and legacy formats
- Allowing for upgrading the encoding in future.

```java
PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
```
**Password Storage Format**
`{id}encodedPasword` : id is an identifier that is used to look up PasswordEncoder should be used, encodedPassword is encoded password
Example: 
```
{noop}password 
{sha256}97cde38028ad898ebc02e690819fa220e88c62e0699403e94fff291cfffaf8410849f27605abcbc0
```
**Encode with Spring Boot CLI**
```
spring encodepassword password
{bcrypt}$2a$10$X5wFBtLrL/kHcmrOGGTrGufsBX8CJ0WpQpF3pgeuxBB/H73BK1DW6
```

Can use `bcrypt, Argon2, PBKDF2, scrypt` algorithm by respective implementation class

**Change Pasword Configuration**
```java
http.passwordManagement(Customizer.withDefaults());
```
When a password manager navigates to `/.well-known/change-password` then Spring Secrurity will redirect your endpoint `/change-password`
or
```java
http.passwordManagement((management) -> management
        .changePasswordPage("/update-password"));
```
navigate to `/update-password`

## Protection Against Exploits
Protection against common exploits. Whenever possible, the protection is enabled by default.

### Cross Site Request Forgery (CSRF)
Situation: You login to your bank web and without logout  -> go to a evil page with same browser -> evil page can you the cookie and do some request to your bank page -> can be lost the money
**Protecting Against CSRF Attacks**
- The **Synchronizer Token Pattern**
- Specifying the **SameSite Attribute** on your seesion cookie.

Both protections require `Safe methods be Idempotent`

**Safe Methods Must be Idempotent**
That mean HTTP methods `GET`, `HEAD`, `OPTIONS`, and `TRACE` shoudn't change the state of application.

**1. Synchronizer Token Pattern**
It is a predominant and comprehensive way to protect against CSRF, ensure each HTTP request requires session cookie and secure random generated value called CSRF token.

HTTP request submmited => server look up the expected CSRF token and compare it against actual CSRF token in HTTP request => false => reject

Key is actual CSRF token is a part of HTTP request, not automatically included by the browser.

Example : The request can add a `_csrf` parameter with secure random value.
```
POST /transfer HTTP/1.1
Host: bank.example.com
Cookie: JSESSIONID=randomid
Content-Type: application/x-www-form-urlencoded

amount=100.00&routingNumber=1234&account=9876&_csrf=4bfd1575-3ad1-4d21-96c7-4ef2d9f86721
```
Server recivied the request and match bw actual csrf and expected csrf token.

**2. SameSite Attribute**
Server set a SameSite attribute in cookie, external sites shouldn't be sent.

Spring Security doesn't directly control the creation of seesion cookie. Spring Session provides support for SameSite atrribute in servlet-based applications.

Example:
```
Set-Cookie: JSESSIONID=randomid; Domain=bank.example.com; Secure; HttpOnly; SameSite=Lax
```
Values :
- `Strict`: any request form same-site includes the cookie:
- `Lax`: Cookie are sent when coming from same-side or comes from top-level navigations (when go to a web site by click from a mail for example) and method is imempotent

**When to use CSRF protection**
Any request that could be processed by browser, disable if that is used only by non-browser clients.

**CSRF protection and JSON** ???
Should we protect JSON request made by JavaScript ? It depends.

**CSRF and StateLess browser Application**
Still can be attacks for example application uses a custom cookie contains all the state in it for authentication (Not JSESSIONID). When the CSRF attrack is made the custom cookie is sent with the request in same manner.

#### CSRF Coniderations
**Logging In**
Steps for attacks.
1. Malicious user perform a CSRF login with malicious user's credentials., the victim is now authenticated as the malicious user.
2. The malicious user then tricks the victim into visiting a webside and entering sensitive information.
3. Then the malicious user can see the sensitive information.

Should have the timeout.
**Logging out**
Seesion timeout

#### CSRF  and Session Timeout
The CSRF token is stored in session. This means that, as soon as the session expires, server doesn't find an expected CSRF token and rejects the HTTP request. Some options to solve timeouts.
- Mitigate the timeout is by using JavaScript to request a CSRF token on form submission.
- have some JavaScript thet lets the user know their session is about to expire, user can click to button to continute and refresh the session.
- Finally, expected CSRF token be stored in a cookie so the CSRF token outlive the session.

#### Multipart (file upload)
Chicken or the egg problem (which came first probleam)
situation: _csrf in body => read in body => file uploaded => external web can upload a file.


**Place CSRF Token in the Body**
Place actual CSRF token in the body of request, the body read before authorization is performed, this mean that anyone can place temporary file on your server. However, only authorized users can submit a file that is processed by your application.
Temprary file upload should have a negligible impact on most server.

**Include CSRF Token in URL**
But it can be leaked

# Security HTTP Response Header

#### Default Security HTTP response Headers
```
Cache-Control: no-cache, no-store, max-age=0, must-revalidate //cache the content of page in browser
Pragma: no-cache
Expires: 0
X-Content-Type-Options: nosniff //all language type
Strict-Transport-Security: max-age=31536000 ; includeSubDomains //work as https
X-Frame-Options: DENY //disable redering pages within a iframe
X-XSS-Protection: 0 //block content
```

# Content Security Policy (CSP)
`Content-Security-Policy: script-src https://trustedscripts.example.com` trust the source in this header
**Referrer Policy**
`Referrer-Policy: same-origin` ; the source where the user was previously

**Feature policy**
enable, disable, and modify the behavior of certain APIs and web features in the browser.
**Permissions Policy**???
**Clear Site Data**
`Clear-Site-Data: "cache", "cookies", "storage", "executionContexts"`  : Nice leanup action to perform on logout
**Custom Headers**
hooks to enable adding custom headers.

# HTTP Requests
- Redirect to HTTPs
- Strict Transport Security : enable by default
- Proxy Server Configuratrion

# Integrations
- Cryptography
- Spring Data
- Java's Concurrency APIs
- Jackson
- Localization
## Cryptography
1. Encryptors
   - BytesEncryptor
   - TextEncryptor
2. Key Generators
   - BytesKeyGenerator
   - StringKeyGenerator
3. Password Encoding
## Spring Data
**Spring Security Configuration**
In Java Configuration, this would look like:
```java
@Bean
public SecurityEvaluationContextExtension securityEvaluationContextExtension() {
	return new SecurityEvaluationContextExtension();
}
```
**Security Expressions within @Query**
```java
@Repository
public interface MessageRepository extends PagingAndSortingRepository<Message,Long> {
	@Query("select m from Message m where m.to.id = ?#{ principal?.id }")
	Page<Message> findInbox(Pageable pageable);
}
```
 check if the Authentication.getPrincipal().getId() is equal to the recipient of the Message

 ## Concurrency Support
 In most environments, Security is stored on a per Thread basis. This means that when work is done on a new Thread, the SecurityContext is lost
 **DelegatingSecurityContextRunnable**
 ```java
 public void run() {
try {
	SecurityContextHolder.setContext(securityContext);
	delegate.run();
} finally {
	SecurityContextHolder.clearContext();
}
```
it makes it seamless to transfer the SecurityContext
You can now easily transfer the SecurityContext of the current Thread to the Thread that invokes the secured service
```java
Runnable originalRunnable = new Runnable() {
public void run() {
	// invoke secured service
}
};

SecurityContext context = SecurityContextHolder.getContext();
DelegatingSecurityContextRunnable wrappedRunnable =
	new DelegatingSecurityContextRunnable(originalRunnable, context);

new Thread(wrappedRunnable).start();
```
**DelegatingSecurityContextExecutor**
accept a delegate Execute

# Spring Security Concurrency Classes
Refer to the Javadoc for additional integrations with both the Java concurrent APIs and the Spring Task abstractions. They are quite self-explanatory once you understand the previous code.

DelegatingSecurityContextCallable

DelegatingSecurityContextExecutor

DelegatingSecurityContextExecutorService

DelegatingSecurityContextRunnable

DelegatingSecurityContextScheduledExecutorService

DelegatingSecurityContextSchedulingTaskExecutor

DelegatingSecurityContextAsyncTaskExecutor

DelegatingSecurityContextTaskExecutor

DelegatingSecurityContextTaskScheduler

## Jackson support
persisting Spring Security related classes
To use it, register the `SecurityJackson2Modules.getModules(ClassLoader)` with ObjectMapper (jackson-databind):
```java
ObjectMapper mapper = new ObjectMapper();
ClassLoader loader = getClass().getClassLoader();
List<Module> modules = SecurityJackson2Modules.getModules(loader);
mapper.registerModules(modules);

// ... use ObjectMapper as normally ...
SecurityContext context = new SecurityContextImpl();
// ...
String json = mapper.writeValueAsString(context);
```

## Localization
All exception messages can be localized
```xml
<bean id="messageSource"
	class="org.springframework.context.support.ReloadableResourceBundleMessageSource">
<property name="basename" value="classpath:org/springframework/security/messages"/>
</bean>
```