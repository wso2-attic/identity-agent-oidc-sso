# identity-agent-oidc-sso

Identity-agent-oidc-sso provides the capability to communicate with your IDP(i.e. WSO2 Identity Server) in a really 
easy manner. You do not have to write any new java code to use this agent in your web application. All the mandatory 
functionality is included already. Further, this agent resides in this repository as module 'agent' you can build the
 agent as a single jar. 

# How to use Agent for a web application.
Process of including OIDC SSO Agent to your web application can be described in three main steps.

First Step: You have to provide the properties that you wish to use. For that you can add the .properties file to your 
web application under the directory: src/main/resources. This properties
 file should include the relevant properties that are required to perform communication with wso2 identity server via
 OIDC flow. 
 
 ```
 NOTE: You can define properties as context-params in the web.xml too. However the effective set of properties have 
 the following priority. 
 Highest -> properties defined in .properties file
 Mid     -> properties defined as context-params
 lowest  -> default values assumed for properties
 
 Thus, higer priority will override the redundant occurrences.
 ``` 
 ```
 The list of properties and their default values assumed by the agent are as follows:

```
Mandatory properties that must be defined either in .properties file or as context-params are as follows.

Property                 | Description                                                          | sample value
------------------------ | -------------------------------------------------------------------- | -------------
OIDC.spName              | Used to uniquely identify service provider.Should be same as in idp. | demo-sso-agent
OIDC.clientId            | This is the client key issued by the IDP(WSO2 IS) during oidc configuration  | adfHtiEzo20hvS6VbqC0QHImfNwa
OIDC.clientSecret        | This is the client secret issued by the IDP(WSO2 IS) during oidc configuration | ayzN4VYrpg12bGylDlTrpPdzQIag

 Second Step: Next step is adding the agent to your web application. If you web application is a Maven web project 
 then add the below dependency. Or else you can add the jar you get after building the module agent.
 
 ```
  <dependency>
     <groupId>org.wso2.carbon.identity.agent.sso.java</groupId>
     <artifactId>identity-agent-oidc-sso-agent</artifactId>
     <version>1.0.0</version>
  </dependency>
 ```

Third Step: Then you have to add the OIDCSSO Filter to your web application's web.xml file as shown below.
 ```
   <filter>
          <filter-name>OIDCSSOAgentFilter</filter-name>
          <filter-class>org.wso2.carbon.identity.sso.agent.OIDCSSOAgentFilter</filter-class>
   </filter>
   <filter-mapping>
          <filter-name>OIDCSSOAgentFilter</filter-name>
          <url-pattern>/oidcsso</url-pattern>
   </filter-mapping>
   <filter-mapping>
          <filter-name>OIDCSSOAgentFilter</filter-name>
          <url-pattern>/callback</url-pattern>
   </filter-mapping>
 ```
 In the above code sample, we can see that three url patterns are mapped to this filter.
 The pattern [/oidcsso]() is used to initiate OIDC flow with the agent. Then the [/callback]() is used to map the 
 callback from the IDP( WSO2 Identity Server).
 
## Sample web application with OIDC Agent

This repository contains a module called 'sample' which contains a simple sample web application the usage of OIDC 
SSO Agent. You can deploy the .war file in sample/target directory into tomcat server.
