# Logger++ Filters for Hunting API Vulnerabilities 
Logger++ is a multithreaded logging extension for Burp Suite. This extension allows advanced filters to be defined to highlight interesting entries or filter logs to only those which match the filter. Here's a collection of my logger++ filters for hunting API vulnerabilities. Capture the API requests and based on that, use these filters.

### 1) API Endpoints   
- REST
  - ```Request.Path CONTAINS "api"```
    - Example: /api/v1/users
  - ```Request.Host CONTAINS "api"```
    - Example: api.target.com/v1/users
- GraphQL 
  - ```Request.Path CONTAINS "graphql"```
    - Example: /api/graphql
 
### 2) API Operations  
  - REST 
    - Read 
      - ```Request.Method == "GET" AND Request.Path CONTAINS "api"```
        - Example: GET /api/users 
    - Create 
      - ```Request.Method == "POST" AND Request.Path CONTAINS "api"```
        - Example: POST /api/users 
    - Update 
      - ```Request.Method == "PUT" AND Request.Path CONTAINS "api"```
        - Example: PUT /api/users/1
    - Delete 
      - ```Request.Method == "DELETE" AND Request.Path CONTAINS "api"```
        - Example: DELETE api/users/1
        
        
  - GraphQL 
    - Read Data
      - ```!(Request.Body CONTAINS "mutation" or Request.Body CONTAINS "subscription")```
    - Create, Update, Delete Data
      - ```Request.Body CONTAINS "mutation"```
      
  - RPC-Style
    - Read Data
      - ```Request.Method == "GET"```
    - Create, Update, Delete 
      - ```Request.Method == "POST"```
      
### 3) API Vulnerabilities 
  - Excessive Data Exposure
    - The API may expose a lot more data than what the client legitimately needs. 
      - 1. Filter all GET requests and look for sensitive data or fields in response body
         - ```Request.Method == "GET" AND Response.Body CONTAINS "email"```
         
  - Mass Assignment 
    - The API takes data that client provides and stores it without proper filtering for whitelisted properties. 
      - 1. Find API objects 
        - Example: 
          - /api/**users**: User Object 
          - /api/**products**: Product Object 
          - /api/**items**: Item Object 
       - 2. Find object properties from GET Requests. You can use the following filter to do this: 
          - ```Request.Method == "GET" AND Request.Path CONTAINS "ResourceName"```
            - Example: ```Request.Method == "GET" AND Request.Path CONTAINS "user"```
       - 3. Add object properties from the previous step in related POST/PUT requests. Use the following filter: 
          - ```Request.Method IN ["POST","PUT"]```
   
   - Injection and Broken Object Level 
      - REST/RPC
        - Path Parameters
          - Example: /api/posts/1 -> Injection point: 1
        - Query String Parameters
          - ```Request.HasGetParam == true```
        - POST/PUT Request Parameters 
          - ```Request.Method IN ["POST","PUT"]```
       - GraphQL 
          - ```Request.Body MATCHES ".*variables\":{.*"```
          
   
   - Security Misconfiguration 
      - CORS: Use both logger++ and AutoRepeater to find the CORS misconfiguration
        - ```!(Request.Headers CONTAINS "Authorization: JWT") AND Response.Status == 200 AND (Response.Headers CONTAINS "Access-Control-Allow-Credentials" OR Response.Headers CONTAINS "Access-Control-Allow-Origin")```
  
  
  
   - Broken Authentication 
      - Token-Based Authentication: 
        - ```Request.Headers CONTAINS "Authorization"```
   
   - SSRF
      - ```(Request.Query MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*" OR Request.Body MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*")```
      
   - Open Redirect
      - ```(Request.Query MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*" OR Request.Body MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*") AND Response.Status IN [301,302]```
      
   - Lack of Resources and Rate Limiting 
      - DOS
        - REST: ```Request.HasGetParam == true AND Request.Query CONTAINS "limit"```
        - GraphQL: ```Request.Body CONTAINS "limit"```
        
