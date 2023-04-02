# Anomaly Detection

## Table of Contents
- [Create Blocklists](./TD.md#create-blocklists)
- [Summary](./TD.md#summary)
- [Update Specific Blocklist](./TD.md#update-a-specific-blocklist)
- [Get All Blocklists](./TD.md#get-all-blocklists)
- [Get Specific Blocklist](./TD.md#get-a-specific-blocklist)
- [Delete Specific Blocklist](./TD.md#delete-a-specific-blocklist)
- [Search for Specific IP Address](./TD.md#search-for-specific-ip-address)
- [Search if IP is Blocked](./TD.md#search-if-ip-is-blocked)
- [Authorization](./TD.md#authorization)
- [Deployment](./TD.md#deployment)
- [Data Storage](./TD.md#data-storage)
- [Testing](./TD.md#testing)
- [Observability](./TD.md#observability)
- [Annex: Swagger contract](./TD.md#annex-swagger-contract)

### Summary
With this application, the Anomaly Detection Team will be able to manage untrusted IP addresses and CIDR ranges by creating and maintaining blocklists.

- To note: during the technical assessment I addressed handling of IPv4 vs IPv6, so that is extended to this tech design. I will also be addressing CIDR ranges even though not explicitly stated in the instructions.

### Create Blocklists
#### User flow
- The user will be able to upload single or multiple blocklist files
- If the upload is successful, each blocklist name and generated UUID will be returned and displayed
- If it is not successful, the error reason will be displayed

<img src="./resources/fileupload_ui.png" height="50%" width="50%">

#### API Requirements
The REST API endpoint that will be used in order to create a blocklist is `/api/blocklists`

![create](./resources/create_flowchart.png)

- The user will be able to upload single or multiple blocklist files which contain IPs.
- It is assumed that once the user is logged in and is able to access this UI they have been authenticated. 
- The API with then validate whether the user is authorized to create a blocklist.
- The API will be able to handle both IPv4 an IPv6 addresses


#### API Example
```
REQUEST EXAMPLE
  curl -XPOST 'https://example.com/api/blocklists' \
  -F 'filename=file1.txt' \
  -F 'filename=file2.txt' \
  -H 'Authorization: Bearer eyJhbG...'
  -H 'Content-Type: multipart/form-data'

RESPONSE PAYLOAD EXAMPLE
{
  "created": [
    { 
      "blocklistID": "uuid-1",
      "blocklistName": "file1"
    },
    { 
      "blocklistID": "uuid-2",
      "blocklistName": "file2"
    },
  ]
}
```

#### Error Handling
- Duplicated IPs in the same blocklist
- Duplicated CIDR ranges
- CIDR range is found within another CIDR range in the same block list
The API will handle the validation scenarios outlined in the above sequence diagram. Any of the errors returned will be displayed in the UI for the user.

#### Considerations
- This endpoint will allow for multiple file upload (eg. if user wants to have a bulk upload of blocklists)
- If the memory usage is too high, then can consider uploading files to a resource manager (eg S3 buckets) and have the API read from there

### Get All Blocklists
#### User flow
- When the user wants to retrieve all block lists, the API will return a paginated list of `BlocklistRecord`s which holds the following info:
  - blocklist name
  - blocklist type (ip or cidr)
  
  <img src="./resources/get_blocklists_ui.png" height="50%" width="50%">

If the user selects a specific blocklist in order to view its contents, the UI will call another API endpoint (detailed [here](./TD.md#get-a-specific-blocklist)).

#### API Requirements
The REST API endpoint that will be used in order to get all blocklists is `/api/blocklists`

<img src="./resources/getall_flowchart.png" height="50%" width="50%">

- This API endpoint will only return the names and types of blocklists
- The type of blocklist can be either:
  - IP addresses (shortened to IP in database)
  - CIDR ranges (shortened to CIDR in database)
- Once the user selects the specific blocklist they wish to view, it will then call the API endpoint `api/blocklists/{id}` to retrieve the specific content for that blocklist.
- All the data returned will be paginated for efficiency and to reduce the amount of information we will have to load into the UI.

#### API Example
```
REQUEST EXAMPLE
  curl -GET 'https://example.com/api/blocklists' \
  -H 'Authorization: Bearer eyJhbG...'

RESPONSE PAYLOAD EXAMPLE
{
  "blocklits": [
    blocklist: {
      "id": "uuid-1",
      "name": "blocklist name1",
      "type": "ip",
      "entries": null
    },
    blocklist: {
      "id": "uuid-5",
      "name": "blocklist name5",
      "type": "cidr",
      "entries": null
    }
  ]
}
```

#### Error Handling
The API will handle the validation scenarios outlined in the above sequence diagram. Any of the errors returned will be displayed in the UI for the user.

### Update a Specific Blocklist
#### User flow
When a user wants to add or delete entries for a specific blocklist, they will have to provide the following:
- list of IPs or CIDRs they want to add
- list of IP or CIDR IDs they want to delete

<img src="./resources/patch_view_ui.png" height="50%" width="50%">

The response will hold the new generated `BlocklistEntry` objects, which will then be appended to the list of available entries to delete. 

#### API Requirements
The REST API endpoint that will update a specific blocklist is `api/blocklists/{id}`

![update](./resources/update_flowchart.png)

### API Example
Request body example
```
REQUEST EXAMPLE
  curl -PATCH 'https://example.com/api/blocklists/uuid-1' \
  -D '{"delete": [1, 2], "add": ["12.13.14.15", "12.13.14.16"]}'
  -H 'Authorization: Bearer eyJhbG...'

RESPONSE PAYLOAD EXAMPLE
{
  "blocklistEntry": [
    {
      "id": 1,
      "value": "12.13.14.15"
      type: ip
    },
    {
      "id": 2,
      "value": "12.13.14.16"
      type: ip
    }
  ]
}
```

#### Considerations
- All or nothing
  - If there is any error for any of the values to be added or deleted, the entire transaction will be rolled back and no edits will be made to the database.
- Scenario: user wants to remove an IP address with id 1 and address value 1.2.3.4. They also want to add 1.2.3.4 within the same request.
  - We will have to load all the IP address values for the IP ids to be removed and check if the IP addresses to add contains any of the IP address to be removed. 
  - If this is the case, return an error. 
- Same error considerations will be followed when adding additional IP(s)/CIDR(s)

#### Error Handling
The API will handle the validation scenarios outlined in the above sequence diagram. Any of the errors returned will be displayed in the UI for the user.

### Get a Specific Blocklist
#### User flow
There will be two ways in which the user can interact with this endpoint via the UI:
1. Retrieve specific blocklist information when viewing all blocklists
2. Search specifically for this blocklist

All the entries for the searched blocklist will be paginated.

<img src="./resources/patch_view_ui.png" height="50%" width="50%">

#### API Requirements
The REST API endpoint that will get a specific blocklist is `api/blocklists/{id}`

![get by id](./resources/getbyid_flowchart.png)

#### API Example
Response payload example
```
REQUEST EXAMPLE
  curl -GET 'https://example.com/api/blocklists/uuid-1' \
  -H 'Authorization: Bearer eyJhbG...'
          
RESPONSE PAYLOAD EXAMPLE
{
  "blocklist": {
    "id": "uuid-1",
    "name": "blocklist name",
    "type": "ip",
    "entries": ["1.2.3.4", "5.6.7.8"] 
  }
}
```
#### Error Handling
The API will handle the validation scenarios outlined in the above sequence diagram. Any of the errors returned will be displayed in the UI for the user.

### Delete a Specific Blocklist
#### User flow
The user will be able to delete a specific blocklist from the list of all blocklists within the UI.

Within the previous UI mock-ups we can see the delete functionality.

#### API Requirements
When the blocklist is selected for deletion, the ID of the blocklist will be passed to the following API endpoint: `api/blocklists/{id}`.

![delete](./resources/delete_flowchart.png)

#### API Example
```
REQUEST EXAMPLE
  curl -X DELETE 'https://example.com/api/blocklists/uuid-1' \
  -H 'Authorization: Bearer eyJhbG...'

RESPONSE PAYLOAD EXAMPLE
HTTP 200
```

#### Considerations and Improvements
- Depending on traffic on those tables and how many records a certain block list can have, the process in which the records are deleted will have to change.
  - Instead of HARD deleting, we can SAFE delete instead.
  - We can introduce a flag or status for each block list, and set that to be true (active) or false (inactive) to represent the state of that blocklist
  - When a blocklist has to be deleted, the API can set this value in the database to indicate that it is no longer "available"
  - Then a "delete job" can be introduced (every X minutes or hours) to join the necessary tables and delete the records
  - This will improve the speed of the delete API when the number of records is massive or the traffic to certain tables is high

### Search For Specific IP Address
#### User flow
When a user wants to search if an IP address within a blocklist, they will be able to pass in the specific IP address into the UI.

<img src="./resources/search_ui.png" height="50%" width="50%">

#### API Requirements
The REST API endpoint that will check if a specific IP address is within a blocklist of type `ip` is `api/search`
The IP address will be appended to the API endpoint as a query parameter. Eg: `api/search?ip=1.2.3.4`

![search](./resources/search_flowchart.png)

#### API Example
```
REQUEST EXAMPLE
  curl -GET 'https://example.com/api/search?ip=1.2.3.4&ip=1.2.3.5' \
  -H 'Authorization: Bearer eyJhbG...'
          
RESPONSE PAYLOAD EXAMPLE
{
  results: {
    {
      "ip": ["1.2.3.4"],
      "blocklistIds": ["uuid-1","uuid-4","uuid-7"]
    },
    {
      "ip": ["1.2.3.5"],
      "blocklistIds": []
    }
  }
}
```

### Search if IP is blocked
#### User flow
If a user wants to check if an IP is blocked, this means that they want to check for the presence of this address within the blocklists of type `ip` as well as if this IP falls within a certain CIDR range for blocklists with type `cidr`

<img src="./resources/search_ui.png" height="50%" width="50%">

#### API Requirements
The REST API endpoint that will check if a specific IP address is blocked `api/blocked`. The IP address will be appended to the API endpoint as a query parameter. Eg: `api/blocked?ip=1.2.3.4`

![blocked](./resources/blocked_flowchart.png)

#### API Examples
```
REQUEST EXAMPLE
  curl -GET 'https://example.com/api/blocked?ip=1.2.3.4' \
  -H 'Authorization: Bearer eyJhbG...'

RESPONSE PAYLOAD EXAMPLE
{
  "ip": "1.2.3.4",
  "isBlocked": true
}
```

#### Considerations
- Check only for one IP
  - This process could be pretty taxing when having to search within the CIDR ranges, so instead of searching for multiple IPs we can limit it for one IP address at a time
  - Could be verified with performance testing and change accordingly

### Authorization
It is assumed that when the user logs into the UI they will already be authenticated.
![auth](./resources/auth_flowchart.png)
For each API endpoint, we will have to focus on securing them with authorization. Depending on whom we want to be able to create, update, delete, and query for certain information, we can limit the accessible roles.

Example:
 - If we have a role based permission system, then we can limit the accessibility of the UI for those who have `ROLE_SECURITY`
 - If we want to constrain it even further, we can use a more fine-grained permission approach and limit the API usage for each permission level.
   - Eg: Creating blocklists is limited to those who have permission `security.write.dev` but deleting can be limited to `security.write.super`. Similarly, with any read endpoint a permission could be `security.read.super`.

In terms of authorizing the request, each request should pass in an JWT access token as a header
- `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`

### Deployment
This application will be deployed on different clusters. As a result, each deployment of the application will be isolated from each other, which means each deployment will have its dedicated database. 
- Example:
  - If this application is deployed in a dev and stage environment, the dev application would not be able to read/write any information from the application within the staging environment.
Using Kubernetes we can address the following:
  - CPU
  - Memory
  - Traffic Manager
  - Horizontal vs vertical scaling
    - Start off with the smallest number of pods and increase if needed
    - Depends on traffic and blocklist size. Can be determined with testing and estimated/expected traffic

Workloads can be better balanced when these requirements and limitations are defined.

#### Deployment Strategies
- Rolling update
  - Gradually replace old version with new version
- Recreate
  - Delete old version then bring up new version, so the two never exist at the same time
- Blue-Green
  - Deploy the new version while the old version is still up
  - All traffic is directed to the old version while testing can be done on the new version
  - When testing passes traffic can be directed to the new version
- Canary
  - Deploy the new version while the old version is still up
  - Subset of traffic is redirected to the new version
  - Increase traffic to new version until it is at 100%

### Data Storage

<img src="./resources/relationalDB.png" height="75%" width="75%">

- Introduce indexes for more efficient searching

#### Concurrency
In order to handle concurrecy when writing to the databases:
- Unique constraint on the blocklist name within the `blocklists` table
- Unique (`blocklist_id`, `address`) composite value in the `ips` table
- Unique (`blocklist_id`, `range`) composite value in the `cidrs` table

### Testing
#### Unit Tests
- Application should include basic unit testing covering all cases

#### Integration / E2E Tests
- Determine if this service works with other dependent services
- Test end to end work flow for use cases

#### Smoke tests
- During deployment process, run happy path smoke tests. If the pass, continue with deployment. If they fail, rollback. Depends on current processes and tooling available.

#### Load Testing
Indicate how frequent load testing should be conducted and the different iterations during test

### Observability
#### Alerting
With our monitors (detailed below) we would be able to dictate what we want to be alerted for. 
Example alerts include (but not limited to): 
- pod is down
- high error rate
- high latency
- high memory usage

#### Monitoring
- Latency
- CPU usage
- Number of requests
- Response time
- Error rate
- Pod health

### Considerations for Production and GA
#### Database Scalability
- Have applications reading on replicas only, have applications write to a single write only database
- If files are too large, upload them to a resource manager (S3 buckets) and have the applications read from there

### Annex: Swagger Contract

```yaml
paths:
  /api/blocklists:
    post:
      summary: Create a blocklist.
      description: Blocklist can contain either only IPs or CIDRs.
      requestBody:
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                filename:
                  type: array
                  items:
                    type: string
                    format: binary
      responses:
        '200':
          description: Blocklist created and UUID generated
          content:
            application/json:
              schema:
                type: object
                properties:
                  created: array
                  items:
                    $ref: '#/components/schemas/BlocklistRecord'
        '400':
          description: Contents of blocklist are invalid, invalid file extension, non-unique name
        '403':
          description: User is not authorized
    get:
      summary: Get all blocklists.
      description: Get a pagniated response of block list IDs.
      responses:
        '200':
          description: Paginated blocklist records returned
          content:
            application/json:
              schema:
                type: array
                itmes:
                  $ref: '#/components/schemas/BlocklistRecord'
        '403':
          description: User is not authorized
         
  /api/blocklists/{id}:
    patch:
      summary: Update or delete a certain blocklist.
      description: Get a pagniated response of block list IDs.
      parameters:
        - in: path
          name: id
          required: true
          description: Blocklist UUID.
          schema:
            type: string
        - in: body
          name: delete
          required: false
          description: List of IP addresses IDs or CIDR ranges IDs to delete
          schema:
            type: array
            items:
              string
        - in: body
          name: add
          required: false
          description: List of IP addresses or CIDR ranges to add
          schema:
            type: array
            items:
              string

      responses:
        '200':
          description: Added IP or CIDR addresses returned
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/BlocklistEntry'
        '403':
          description: User is not authorized
        '404':
          description: Blocklist not found
          
    get:
      summary: Get a specific blocklist and its contents.
      parameters:
        - in: path
          name: id
          required: true
          description: Blocklist UUID.
          schema:
            type: string
      responses:
        '200':
          description: Found blocklist is returned
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Blocklist'
        '403':
          description: User is not authorized
        '404':
          description: Blocklist not found
    delete:
      summary: Delete a specific blocklist and its contents.
      parameters:
        - in: path
          name: id
          required: true
          description: Blocklist UUID.
          schema:
            type: string
      responses:
        '200':
          description: Successfully deleted blocklist
        '403':
          description: User is not authorized
        '404': 
          description: Blocklist not found
          
  /api/search:
    get:
      summary: Search if a specific IP is in a blocklist.
      parameters:
        - in: query
          name: ip
          required: true
          description: IP address.
          schema:
            type: string
      responses:
        '200':
          description: Successfully deleted blocklist
          content:
            type: application/json
            schema:
              type: array
              itmes:
                $ref: '#/components/schemas/IPSearchResult'

        '403':
          description: User is not authorized
        '404':
          description: Blocklist not found
          
  /api/blocked:
    get:
      summary: Search if a specific IP is blocked (in an IP blocklist or found in a CIDR range).
      parameters:
        - in: query
          name: ip
          required: true
          description: IP address
          schema:
            type: string
      responses:
        '200':
          description: IP address and if it is blocked
          content:
            type: application/json
            schema:
              type: object
              properties:
                - name: ipaddress
                  type: string
                - name: isBlocked
                  type: boolean
        '403':
          description: User is not authorized

components:
  schemas:
    Blocklist:
      type: object
      properties:
        id:
          type: string
        name:
          type: string
        type:
          type: string
          enum: [ip, cidr]
        entries:
          type: array
          items:
            $ref: BlocklistEntry
      required:
        - id
        - name
        - type
    
    BlocklistRecord:
      type: object
      properties:
        id:
          type: string
        name:
          type: string
        type:
          type: string
          enum: [ip, cidr]
        entries:
          type: array
          items:
            BlocklistEntry
        required:
          - id
          - name
          - type

    BlocklistEntry:
      type: object
      properties:
        id:
          type: integer
        value:
          type: string
        type:
          description: if the value is an IP address or CIDR
          type: string
          enum: [ip, cidr]
      required:
        - id
        - value
        - type
            
    IPSearchResult:
    type: object
    properties:
      result:
        type: array
        items:
          type: object
          properties:
            ip:
              type: string
              description: IP address searched
            blocklistIds:
              description: Blocklist IDs where the IP is found
              type: array
              items:
                string

```
