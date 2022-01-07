[comment]: # "Auto-generated SOAR connector documentation"
# EclecticIQ app

Publisher: EclecticIQ  
Connector Version: 1\.3\.1  
Product Vendor: EclecticIQ  
Product Name: TIP  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.6\.19142  

EclecticIQ Platform integration

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a TIP asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**tip\_uri** |  required  | string | EclecticIQ Platform Address
**tip\_user** |  required  | string | EclecticIQ Username
**tip\_password** |  required  | password | EclecticIQ Password/Token
**tip\_group** |  optional  | string | EclecticIQ Group Name for Entities
**tip\_of\_id** |  optional  | numeric | EclecticIQ Outgoing Feed ID \# for Polling
**tip\_ssl\_check** |  optional  | boolean | EclecticIQ SSL Cert Check
**tip\_proxy\_uri** |  optional  | string | Proxy Server Address
**tip\_proxy\_user** |  optional  | string | Proxy Server Username
**tip\_proxy\_password** |  optional  | password | Proxy Server Password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[domain reputation](#action-domain-reputation) - Queries domain info  
[email reputation](#action-email-reputation) - Queries email info  
[file reputation](#action-file-reputation) - Queries for file reputation info  
[ip reputation](#action-ip-reputation) - Queries IP info  
[url reputation](#action-url-reputation) - Queries URL info  
[create sighting](#action-create-sighting) - Create sighting in EclecticIQ TIP  
[create indicator](#action-create-indicator) - Create an indicator in EclecticIQ TIP  
[query entities](#action-query-entities) - Query EclecticIQ Platform for entities  
[on poll](#action-on-poll) - Callback action for the on\_poll ingest functionality  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'domain reputation'
Queries domain info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.data\.0 | string | 
action\_result\.data\.0\.created | string | 
action\_result\.data\.0\.last\_updated | string | 
action\_result\.data\.0\.maliciousness | string | 
action\_result\.data\.0\.platform\_link | string | 
action\_result\.data\.0\.source\_name | string | 
action\_result\.summary\.important\_data | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'email reputation'
Queries email info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Email to query | string |  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.data\.0 | string | 
action\_result\.data\.0\.created | string | 
action\_result\.data\.0\.last\_updated | string | 
action\_result\.data\.0\.maliciousness | string | 
action\_result\.data\.0\.platform\_link | string | 
action\_result\.data\.0\.source\_name | string | 
action\_result\.summary\.important\_data | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'file reputation'
Queries for file reputation info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | File hash to query | string |  `hash`  `sha256`  `sha1`  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `sha256`  `sha1`  `md5` 
action\_result\.data\.0 | string | 
action\_result\.data\.0\.created | string | 
action\_result\.data\.0\.last\_updated | string | 
action\_result\.data\.0\.maliciousness | string | 
action\_result\.data\.0\.platform\_link | string | 
action\_result\.data\.0\.source\_name | string | 
action\_result\.summary\.important\_data | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'ip reputation'
Queries IP info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.0 | string | 
action\_result\.data\.0\.created | string | 
action\_result\.data\.0\.last\_updated | string | 
action\_result\.data\.0\.maliciousness | string | 
action\_result\.data\.0\.platform\_link | string | 
action\_result\.data\.0\.source\_name | string | 
action\_result\.summary\.important\_data | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'url reputation'
Queries URL info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to query | string |  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.0 | string | 
action\_result\.data\.0\.created | string | 
action\_result\.data\.0\.last\_updated | string | 
action\_result\.data\.0\.maliciousness | string | 
action\_result\.data\.0\.platform\_link | string | 
action\_result\.data\.0\.source\_name | string | 
action\_result\.summary\.important\_data | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create sighting'
Create sighting in EclecticIQ TIP

Type: **contain**  
Read only: **False**

The TIP group name must be provided for this action to run successfully\. Either in the source parameter or the asset configuration\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sighting\_value** |  required  | Observable value | string | 
**sighting\_type** |  required  | Observable type | string | 
**sighting\_maliciousness** |  optional  | Observalble maliciousness | string | 
**confidence\_value** |  required  | Confidence value | string | 
**sighting\_description** |  optional  | Sighting description | string | 
**sighting\_title** |  required  | Sighting title | string | 
**tags** |  required  | Sighting tags delimited by ',' | string | 
**impact\_value** |  required  | Impact value | string | 
**observable\_2\_maliciousness** |  optional  | Observable 2 maliciousness | string | 
**observable\_2\_type** |  optional  | Observable 2 type | string | 
**observable\_2\_value** |  optional  | Observable 2 value | string | 
**observable\_3\_maliciousness** |  optional  | Observable 3 maliciousness | string | 
**observable\_3\_type** |  optional  | Observable 3 type | string | 
**observable\_3\_value** |  optional  | Observable 3 value | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.confidence\_value | string | 
action\_result\.parameter\.impact\_value | string | 
action\_result\.parameter\.observable\_2\_maliciousness | string | 
action\_result\.parameter\.observable\_2\_type | string | 
action\_result\.parameter\.observable\_2\_value | string | 
action\_result\.parameter\.observable\_3\_maliciousness | string | 
action\_result\.parameter\.observable\_3\_type | string | 
action\_result\.parameter\.observable\_3\_value | string | 
action\_result\.parameter\.sighting\_description | string | 
action\_result\.parameter\.sighting\_maliciousness | string | 
action\_result\.parameter\.sighting\_title | string | 
action\_result\.parameter\.sighting\_type | string | 
action\_result\.parameter\.sighting\_value | string | 
action\_result\.parameter\.tags | string | 
action\_result\.data\.0 | string | 
action\_result\.summary\.important\_data | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create indicator'
Create an indicator in EclecticIQ TIP

Type: **contain**  
Read only: **False**

The TIP group name must be provided for this action to run successfully\. Either in the source parameter or the asset configuration\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**observable\_dictionary** |  required  | Observable dictionary | string | 
**indicator\_type** |  required  | Indicator type | string | 
**confidence\_value** |  required  | Confidence value | string | 
**indicator\_description** |  optional  | Indicator description | string | 
**indicator\_title** |  required  | Indicator title | string | 
**tags** |  required  | Indicator tags delimited by ',' | string | 
**impact\_value** |  required  | Impact value | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.confidence\_value | string | 
action\_result\.parameter\.impact\_value | string | 
action\_result\.parameter\.indicator\_description | string | 
action\_result\.parameter\.indicator\_title | string | 
action\_result\.parameter\.indicator\_type | string | 
action\_result\.parameter\.observable\_dictionary | string | 
action\_result\.parameter\.tags | string | 
action\_result\.data\.0 | string | 
action\_result\.summary\.important\_data | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'query entities'
Query EclecticIQ Platform for entities

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  optional  | Observable value to query related entities | string |  `ip`  `hash`  `domain`  `url`  `sha1`  `sha256`  `md5`  `sha512` 
**entity\_value** |  optional  | Text to search inside entity title\. To find exact phrase wrap it with double\-quotes \("\) | string | 
**entity\_type** |  optional  | Type of entity to query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.entity\_type | string | 
action\_result\.parameter\.entity\_value | string | 
action\_result\.parameter\.query | string |  `ip`  `hash`  `domain`  `url`  `sha1`  `sha256`  `md5`  `sha512` 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.extract\_classification | string | 
action\_result\.data\.\*\.extract\_confidence | string | 
action\_result\.data\.\*\.extract\_kind | string | 
action\_result\.data\.\*\.extract\_value | string | 
action\_result\.data\.\*\.source\_name | string | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.threat\_start | string | 
action\_result\.data\.\*\.title | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'on poll'
Callback action for the on\_poll ingest functionality

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_id** |  optional  | Container IDs to limit the ingestion to | string | 
**start\_time** |  optional  | Start of time range, in epoch time \(milliseconds\) | numeric | 
**end\_time** |  optional  | End of time range, in epoch time \(milliseconds\) | numeric | 
**container\_count** |  optional  | Maximum number of container records to query for | numeric | 
**artifact\_count** |  optional  | Maximum number of artifact records to query for | numeric | 
**feed\_ids** |  optional  | TIP feed IDs delimited by "," | string | 

#### Action Output
No Output