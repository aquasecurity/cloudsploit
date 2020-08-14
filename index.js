#!/usr/bin/env node

var engine = require('./engine');

var AWSConfig;
var AzureConfig;
var GitHubConfig;
var OracleConfig;
var GoogleConfig;

// OPTION 1: Configure service provider credentials through hard-coded config objects

// AWSConfig = {
//     accessKeyId: '',
//     secretAccessKey: '',
//     sessionToken: '',
//     region: 'us-east-1'
// };

// AzureConfig = {
//     ApplicationID: '',          // A.K.A ClientID
//     KeyValue: '',               // Secret
//     DirectoryID: '',            // A.K.A TenantID or Domain
//     SubscriptionID: '',
//     location: 'East US'
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

// Now execute the scans using the defined configuration information.
if (!settings.config) {
    // AWS will handle the default credential chain without needing a credential file
    console.log('INFO: No config file provided, using default AWS credential chain.');
    return engine(cloudConfig, settings);
}

// If "compliance=cis" is passed, turn into "compliance=cis1 and compliance=cis2"
if (settings.compliance && settings.compliance.indexOf('cis') > -1) {
    if (settings.compliance.indexOf('cis1') === -1) {
        settings.compliance.push('cis1');
    }
    if (settings.compliance.indexOf('cis2') === -1) {
        settings.compliance.push('cis2');
    }
    settings.compliance = settings.compliance.filter(function(e) { return e !== 'cis'; });
}

console.log(`INFO: Using CloudSploit config file: ${settings.config}`);

try {
    var config = require(settings.config);
} catch(e) {
    console.error('ERROR: Config file could not be loaded. Please ensure you have copied the config_example.js file to config.js');
    process.exit(1);
}
if(process.env.GOOGLE_APPLICATION_CREDENTIALS){
    GoogleConfig = require(process.env.GOOGLE_APPLICATION_CREDENTIALS);
    GoogleConfig.project = GoogleConfig.project_id;
}

// Custom settings - place plugin-specific settings here
var settings = {
    plainTextParameters: {
        secretWords: [
            'secret', 'password', 'privatekey'
        ]
    }
};

// If running in GovCloud, uncomment the following
// settings.govcloud = true;

// If running in AWS China, uncomment the following
// settings.china = true;

function checkRequiredKeys(obj, keys) {
    keys.forEach(function(key){
        if (!obj[key] || !obj[key].length) {
            console.error(`ERROR: The credential config did not contain a valid value for: ${key}`);
            process.exit(1);
        }
    });
}

if (config.credentials.aws.credential_file) {
    cloudConfig = loadHelperFile(config.credentials.aws.credential_file);
    if (!cloudConfig || !cloudConfig.accessKeyId || !cloudConfig.secretAccessKey) {
        console.error('ERROR: AWS credential file does not have accessKeyId or secretAccessKey properties');
        process.exit(1);
    }
} else if (config.credentials.aws.access_key) {
    checkRequiredKeys(config.credentials.aws, ['secret_access_key']);
    cloudConfig = {
        accessKeyId: config.credentials.aws.access_key,
        secretAccessKey: config.credentials.aws.secret_access_key,
        sessionToken: config.credentials.aws.session_token,
        region: 'us-east-1'
    };
} else if (config.credentials.azure.credential_file) {
    settings.cloud = 'azure';
    cloudConfig = loadHelperFile(config.credentials.azure.credential_file);
    if (!cloudConfig || !cloudConfig.ApplicationID || !cloudConfig.KeyValue || !cloudConfig.DirectoryID || !cloudConfig.SubscriptionID) {
        console.error('ERROR: Azure credential file does not have ApplicationID, KeyValue, DirectoryID, or SubscriptionID');
        process.exit(1);
    }
    cloudConfig.location = 'East US';
} else if (config.credentials.azure.application_id) {
    settings.cloud = 'azure';
    checkRequiredKeys(config.credentials.azure, ['key_value', 'directory_id', 'subscription_id']);
    cloudConfig = {
        ApplicationID: config.credentials.azure.application_id,
        KeyValue: config.credentials.azure.key_value,
        DirectoryID: config.credentials.azure.directory_id,
        SubscriptionID: config.credentials.azure.subscription_id,
        location: 'East US'
    };
} else if (config.credentials.google.credential_file) {
    settings.cloud = 'google';
    cloudConfig = loadHelperFile(config.credentials.google.credential_file);
} else if (config.credentials.google.project) {
    settings.cloud = 'google';
    checkRequiredKeys(config.credentials.google, ['client_email', 'private_key']);
    cloudConfig = {
        type: 'service_account',
        project: config.credentials.google.project,
        client_email: config.credentials.google.client_email,
        private_key: config.credentials.google.private_key,
    };
} else if (config.credentials.oracle.credential_file) {
    settings.cloud = 'oracle';
    cloudConfig = loadHelperFile(config.credentials.oracle.credential_file);
    if (!cloudConfig || !cloudConfig.tenancyId || !cloudConfig.compartmentId || !cloudConfig.userId || !cloudConfig.keyValue) {
        console.error('ERROR: Oracle credential file does not have tenancyId, compartmentId, userId, or keyValue');
        process.exit(1);
    }

    cloudConfig.RESTversion = '/20160918';
    cloudConfig.region = 'us-ashburn-1';
} else if (config.credentials.oracle.tenancy_id) {
    settings.cloud = 'oracle';
    checkRequiredKeys(config.credentials.oracle, ['compartment_id', 'user_id', 'key_fingerprint', 'key_value']);
    cloudConfig = {
        RESTversion: '/20160918',
        tenancyId: config.credentials.oracle.tenancy_id,
        compartmentId: config.credentials.oracle.compartment_id,
        userId: config.credentials.oracle.user_id,
        keyFingerprint: config.credentials.oracle.key_fingerprint,
        keyValue: config.credentials.oracle.key_value,
        region: 'us-ashburn-1',
    };
} else if (config.credentials.github.credential_file) {
    settings.cloud = 'github';
    cloudConfig = loadHelperFile(config.credentials.github.credential_file);
} else if (config.credentials.github.token) {
    settings.cloud = 'github';
    checkRequiredKeys(config.credentials.github, ['url', 'login']);
    cloudConfig = {
        token: config.credentials.github.token,
        url: config.credentials.github.url,
        organization: config.credentials.github.organization,
        login: config.credentials.github.login
    };
} else {
    console.error('ERROR: Config file does not contain any valid credential configs.');
    process.exit(1);
}

// Now execute the scans using the defined configuration information.
engine(cloudConfig, settings);
