# Logger++ Filters for Hunting API Vulnerabilities 
Logger++ is a multithreaded logging extension for Burp Suite. This extension allows advanced filters to be defined to highlight interesting entries or filter logs to only those which match the filter. Here's a collection of my logger++ filters for hunting API vulnerabilities. Capture the API requests and based on that, use these filters.

### 1) API Endpoints   
- REST/RPC
  - ```Request.Path CONTAINS "api" or Request.Host CONTAINS "api"```
    - Example: /api/v1/users, api.target.com/v1/users
  - ```Request.Path CONTAINS "v1"```: Change the "v" based on logged requests  
- GraphQL 
  - ```Request.Path CONTAINS "graphql"```
    - Example: /api/graphql
 
### 2) API Operations  
  - REST 
    - Read 
      - ```Request.Method == "GET"```
        - Example: GET /api/users 
    - Create 
      - ```Request.Method == "POST"```
        - Example: POST /api/users 
    - Update 
      - ```Request.Method == "PUT"```
        - Example: PUT /api/users/1
    - Delete 
      - ```Request.Method == "DELETE"```
        - Example: DELETE api/users/1
    - Create, Update, Delete
      - ```Request.Method IN ["POST","PUT","DELETE"]```
    - API Endpoint + Different API Operations 
      - Example: GET /v1/users 
        - Filter GET Requests in this API: ```Request.Method == "GET" AND Request.Path CONTAINS "v1"```
        
  - GraphQL 
    - Read (Query)
      - ```!(Request.Body CONTAINS "mutation" or Request.Body CONTAINS "subscription")```
    - Create, Update, Delete (Mutation)
      - ```Request.Body CONTAINS "mutation"```
      
  - RPC
    - Read 
      - ```Request.Method == "GET"```
    - Create, Update, Delete 
      - ```Request.Method == "POST"```
      
### 3) API Vulnerabilities 
  - Excessive Data Exposure
    - The API may expose a lot more data than what the client legitimately needs. 
      - 1. Filter all of the GET requests and look for sensitive data in response body
         - ```Request.Method == "GET" AND Response.Body CONTAINS "FIELD"```: FIELD: email, token, etc. 
         
  - Mass Assignment 
    - The API takes data that client provides and stores it without proper filtering for whitelisted properties. 
      - 1. Find the API objects 
        - Example: 
          - /api/**users**: User Object 
          - /api/**products**: Product Object 
          - /api/**items**: Item Object 
       - 2. Find the object properties from GET Requests. Use the following filter to do this: 
          - ```Request.Method == "GET" AND Request.Path CONTAINS "ResourceName"```
            - Example: ```Request.Method == "GET" AND Request.Path CONTAINS "user"```
       - 3. Add object properties from the previous step to related POST/PUT requests. Use the following filter: 
          - ```Request.Method IN ["POST","PUT"]```
   
   - Injection and Broken Object Level 
      - REST/RPC
        - Path Parameters
          - Example: /api/posts/1 
        - Query String Parameters
          - ```Request.HasGetParam == true```
        - POST/PUT Request Parameters 
          - ```Request.Method IN ["POST","PUT"]```
       - GraphQL 
          - ```Request.Body MATCHES ".*variables\":{.*"```
          
   
   - Security Misconfiguration 
      - CORS: Use both logger++ and AutoRepeater to find the CORS misconfiguration, You can also use other tools or extensions to automte the process. 
        - ```!(Request.Headers CONTAINS "Authorization: JWT") AND (Response.Headers CONTAINS "Access-Control-Allow-Credentials" OR Response.Headers CONTAINS "Access-Control-Allow-Origin")```
  
  
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
   - XSS
      - Check for reflected parameters 
        - ```Response.Reflections > 0```
   
        
