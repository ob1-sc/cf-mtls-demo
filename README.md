## Walkthrough: Cloud Foundry mTLS using the X-Forwarded-Client-Cert (XFCC) header and Java Buildpack Client Certificate Mapper

## Introduction

Prior to the introduction of mTLS using XFCC and the Java Buildpack Client Certificate Mapper, the only available option for mTLS was through TCP Routing to pass through the TLS handshake to the application, this approach bypasses all the layer-7 HTTP features of GoRouter, including context-path routing, transparent retries, and sticky sessions. 

This walkthrough aims to show a basic configuration of the new features using Cloud Foundry on bosh-lite with a simple Spring Boot application. In the walkthrough, we are using Cloud Foundry with SSL/TLS terminated at the GoRouter

### Step 1 - Download Example Source Code 

    $ cd [GITHUB HOME]
    $ git clone https://github.com/ob-sc/cf-xfcc-demo

### Step 2 - Deploy Cloud Foundry using bosh-lite (BOSH2)

For windows environments see: https://github.com/goettw/bosh-lite-windows-bosh-client2

For Linux environments see: http://www.starkandwayne.com/blog/bosh-lite-on-virtualbox-with-bosh2/

### Step 3 - Ensure SSL/TLS termination at GoRouter only

Check that the [cf-deployment.yml](https://github.com/cloudfoundry/cf-deployment/blob/master/cf-deployment.yml) is correctly configured based on the [instructions in the Cloud Foundry Admin Guide](https://docs.cloudfoundry.org/adminguide/securing-traffic.html#gorouter_term):

```yaml
  - name: gorouter
    release: routing
    properties:
      router:
        enable_ssl: true
        tls_pem:
        - cert_chain: "((router_ssl.certificate))"
          private_key: "((router_ssl.private_key))"
      
```

### Step 4 - Ensure Client Certificates are mapped to XFCC header

Applications that require mutual TLS (mTLS) need metadata from Client Certificates to authorize requests. Cloud Foundry supports this use case without bypassing layer-7 load balancers and the GoRouter. The following configuration will ensure Client Certificates are mapped to the XFCC header when the GoRouter is configured to terminate SSL/TLS.

```yaml
  - name: gorouter
    release: routing
    properties:
      router:
        forwarded_client_cert: sanitize_set
      
```

### Step 5 - Generate a Client Certificate and Authority


### Step 6 - Add Certificate Authority to validate certificates during mTLS handshake

We will add our Client Certificate Authority to the list of authorities used to validate certificates provided by remote systems during mTLS handshakes. Modify the GoRouter configuration as follows:

```yaml
  - name: gorouter
    release: routing
    properties:
      router:
        ca_certs: "((router_ca_certs))"
```

---
**NOTE**

Given the the GoRouter is initiating the mTLS handshake does this mean that all apps have to present a Client Certificate? The answer is no as by default the GoRouter is configured to only ask for a Client Certificate to be presented if it is available. We will see in a later step that we are still able to access applications even if a Client Certificate is not available.

---

### Step 7 - Redeploy with config changes

Redeploy with the new configuration and providing your ca_certs in a var file (note the additional ***--var-file <PATH TO GENERATED CERTS>/router_ca_certs=ca_certs.txt*** flag):

	$ bosh -d cf deploy ~/workspace/cf-deployment/cf-deployment.yml --var-file <PATH TO GENERATED CERTS>/router_ca_certs=ca_certs.txt -o ~/workspace/cf-deployment/operatio ns/bosh-lite.yml --vars-store ~/deployments/vbox/deployment-vars.yml -v system_domain=bosh-lite.com
	

### Step 8 - Test access to app without Client Certificate

The insecure server is a simple Spring Boot application that exposes a simple ***/header*** endpoint that when called (***GET*** request) will return all available headers. To package and deploy the app (assuming you have targeted your bosh-lite CF deployment):

    $ cd [GITHUB HOME]/cf-mtls-demo/insecure-server
    $ mvn clean package
    $ cf push
    

Using a web browser (tested with Firefox), browse to https://insecure-server.bosh-lite.com/headers (assuming your cf deployment system domain is bosh-lite.com) and you should see all available headers. 

---
**NOTE**

Even thought the GoRouter is configured with the additional Certificate Authority you will not have been prompted to present a Client Certificate (you will need to accept the Server Certificate though). This demonstrates that even though the GoRouter has been configured for mTLS it will not affect deployed applications that do not require a Client Certificate.

---

### Step 9 - Test access to secured app without Client Certificate

The secure server is a simple Spring Boot application that is configured to only authenticate the user ***joe.bloggs@acme.com*** from a Client Certificate (using X509 based pre-authenticate). 

The app exposes a simple ***/user*** endpoint that when called (***GET*** request) will return the user name as well as a simple ***/header*** endpoint that when called (***GET***

***

 request) will return the all available headers.

The main differences between the insecure-server and secure-server apps are as follows:

- Additional Spring Security Dependency:

```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

- Security configuration to check for a valid user from the X509 Certificate (in our case ***joe.bloggs@acme.com***):

```java
@EnableWebSecurity
public class HttpSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${valid-user}")
    private String validUser;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated()
                .and()
                .x509()
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                .userDetailsService(userDetailsService());
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) {
                if (username.equals(validUser)) {
                    return new User(username, "", AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
                } else {
                    throw new UsernameNotFoundException("Invalid user: " + username);
                }
            }
        };
    }
}
```

---
**NOTE**

The [Java Buildpack Client Certificate mapper](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/) is automatically adding a Servlet Filter that maps the X-Forwarded-Client-Cert to the javax.servlet.request.X509Certificate Servlet attribute that we are using to authenticate

---

- Additional ***/user*** end point that prints the username:

```java
    @RequestMapping(value = "/user")
    public String user(@RequestHeader HttpHeaders headers, Principal principal) {
        UserDetails currentUser = (UserDetails) ((Authentication) principal).getPrincipal();
        return "Hello " + currentUser.getUsername();
    }
```

If we call either the ***/user*** or ***/headers*** end point in the secure-server app, we will get a 403 Forbidden exception as no Client Certificate is present.

### Step 10 - Test access to secured app with client certificate

To authenticate we can add our Client Certificate in Firefox security settings:

Now when we call either the ***/user*** or ***/headers*** end point we will be prompted for our Client Certificate, once selected the app will authenticate joe.bloggs@acme.com and allow access.

---
**NOTE**

When calling the ***/headers*** end point we can see the additional ***X-Forwarded-Client-Cert***  header that has been added by the GoRouter from the Client Certificate. This header is picked up by the Java Buildpack Client Certificate Mapper Servlet Filter and maps it to the javax.servlet.request.X509Certificate Servlet attribute so it can be used for authentication.

---

