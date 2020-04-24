#!/usr/bin/env node

var engine = require('./engine');

var AWSConfig;
var AzureConfig;
var GitHubConfig;
var OracleConfig;
var GoogleConfig;

// OPTION 1: Configure service provider credentials through hard-coded config objects

// AWSConfig = {
//  accessKeyId: '',
//  secretAccessKey: '',
//  sessionToken: '',
//  region: 'us-east-1'
// };

// AzureConfig = {
//  ApplicationID: '',          // A.K.A ClientID
//  KeyValue: '',               // Secret
//  DirectoryID: '',            // A.K.A TenantID or Domain
//  SubscriptionID: '',
//  location: 'East US'
// };

// GitHubConfig = {
//  token: '',                      // GitHub app token
//  url: 'https://api.github.com',  // BaseURL if not using public GitHub
//  organization: false,            // Set to true if the login is an organization
//  login: ''                       // The login id for the user or organization
// };

// Oracle Important Note:
// Please read Oracle API's key generation instructions: config/_oracle/keys/Readme.md
// You will want an API signing key to fill the keyFingerprint and privateKey params
// OracleConfig = {
//  RESTversion: '/20160918',
//  tenancyId: 'ocid1.tenancy.oc1..',
//  compartmentId: 'ocid1.compartment.oc1..',
//  userId: 'ocid1.user.oc1..',
//  keyFingerprint: 'YOURKEYFINGERPRINT',
//  keyValue: "-----BEGIN PRIVATE KEY-----\nYOUR-PRIVATE-KEY-GOES-HERE\n-----END PRIVATE KEY-----\n",
//  region: 'us-ashburn-1',
// };

// GoogleConfig = {
//     "type": "service_account",
//     "project": "your-project-name",
//     "client_email": "cloudsploit@your-project-name.iam.gserviceaccount.com",
//     "private_key": "-----BEGIN PRIVATE KEY-----\nYOUR-PRIVATE-KEY-GOES-HERE\n-----END PRIVATE KEY-----\n",
// };

// OPTION 2: Import a service provider config file containing credentials

// AWSConfig = require(__dirname + '/aws_credentials.json');
// AzureConfig = require(__dirname + '/azure_credentials.json');
// GitHubConfig = require(__dirname + '/github_credentials.json');
// OracleConfig = require(__dirname + '/oracle_credentials.json');
// GoogleConfig = require(__dirname + '/google_credentials.json');

// OPTION 3: ENV configuration with service provider env vars
if(process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY){
    AWSConfig = {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey:  process.env.AWS_SECRET_ACCESS_KEY,
        sessionToken: process.env.AWS_SESSION_TOKEN,
        region: process.env.AWS_DEFAULT_REGION || 'us-east-1'
    };
}

if(process.env.AZURE_APPLICATION_ID && process.env.AZURE_KEY_VALUE){
    AzureConfig = {
        ApplicationID: process.env.AZURE_APPLICATION_ID,
        KeyValue:  process.env.AZURE_KEY_VALUE,
        DirectoryID: process.env.AZURE_DIRECTORY_ID,
        SubscriptionID: process.env.AZURE_SUBSCRIPTION_ID,
        region: process.env.AZURE_LOCATION || 'eastus'
    };
}

if(process.env.GITHUB_LOGIN){
    GitHubConfig = {
        url: process.env.GITHUB_URL || 'https://api.github.com',
        login: process.env.GITHUB_LOGIN,
        organization: process.env.GITHUB_ORG ? true : false
    };
}

if(process.env.ORACLE_TENANCY_ID && process.env.ORACLE_USER_ID){
    OracleConfig = {
        RESTversion: process.env.ORACLE_REST_VERSION,
        tenancyId: process.env.ORACLE_TENANCY_ID,
        compartmentId: process.env.ORACLE_COMPARTMENT_ID,
        userId:  process.env.ORACLE_USER_ID,
        keyFingerprint: process.env.ORACLE_KEY_FINGERPRINT,
        region: process.env.ORACLE_REGION || 'us-ashburn-1'
    };
}

if(process.env.GOOGLE_PROJECT_ID && process.env.GOOGLE_API_KEY){
    GoogleConfig = {
        project: process.env.GOOGLE_PROJECT_ID,
        API_KEY:  process.env.GOOGLE_API_KEY,
        serviceId: process.env.GOOGLE_SERVICE_ID,
        region: process.env.GOOGLE_DEFAULT_REGION || 'us-east1'
    };
}
if(process.env.GOOGLE_APPLICATION_CREDENTIALS){
    GoogleConfig = require(process.env.GOOGLE_APPLICATION_CREDENTIALS);
    GoogleConfig.project = GoogleConfig.project_id;
}

// Custom settings - place plugin-specific settings here
var settings = {};

// If running in GovCloud, uncomment the following
// settings.govcloud = true;

// If running in AWS China, uncomment the following
// settings.china = true;

// If you want to disable AWS pagination, set the setting to false here
settings.paginate = true;

settings.debugTime = false;

// Now execute the scans using the defined configuration information.
engine(AWSConfig, AzureConfig, GitHubConfig, OracleConfig, GoogleConfig, settings);
