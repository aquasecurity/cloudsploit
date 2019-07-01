#!/usr/bin/env node

var engine = require('./engine');

var AWSConfig;
var AzureConfig;
var GitHubConfig;
var OracleConfig;

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
//  privateKey: fs.readFileSync(__dirname + '/config/_oracle/keys/YOURKEYNAME.pem', 'ascii'),
//  region: 'us-ashburn-1',
// };

// OPTION 2: Import a service provider config file containing credentials

// AWSConfig = require(__dirname + '/aws_credentials.json');
// AzureConfig = require(__dirname + '/azure_credentials.json');
// GitHubConfig = require(__dirname + '/github_credentials.json');
// OracleConfig = require(__dirname + '/oracle_credentials.json');

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

// Custom settings - place plugin-specific settings here
var settings = {};

// If running in GovCloud, uncomment the following
// settings.govcloud = true;

// If you want to disable AWS pagination, set the setting to false here
settings.paginate = true;

// Now execute the scans using the defined configuration information.
engine(AWSConfig, AzureConfig, GitHubConfig, OracleConfig, settings);
