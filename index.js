#!/usr/bin/env node

var engine = require('./engine');

console.log(`
   _____ _                 _  _____       _       _ _   
  / ____| |               | |/ ____|     | |     (_) |  
 | |    | | ___  _   _  __| | (___  _ __ | | ___  _| |_ 
 | |    | |/ _ \\| | | |/ _\` |\\___ \\| '_ \\| |/ _ \\| | __|
 | |____| | (_) | |_| | (_| |____) | |_) | | (_) | | |_ 
  \\_____|_|\\___/ \\__,_|\\__,_|_____/| .__/|_|\\___/|_|\\__|
                                   | |                  
                                   |_|                  
`);

try {
    var config = require('./config.js');
} catch(e) {
    console.error('ERROR: Config file could not be loaded. Please ensure you have copied the config_example.js file to config.js');
    process.exit(1);
}

var AWSConfig;
var AzureConfig;
var GitHubConfig;
var OracleConfig;
var GoogleConfig;

function loadHelperFile(path) {
    try {
        var contents = require(path);
    } catch (e) {
        console.error(`ERROR: The credential file could not be loaded ${path}`);
        console.error(e);
        process.exit(1);
    }
    return contents;
}

function checkRequiredKeys(obj, keys) {
    keys.forEach(function(key){
        if (!obj[key] || !obj[key].length) {
            console.error(`ERROR: The credential config did not contain a valid value for: ${key}`);
            process.exit(1);
        }
    });
}

if (config.credentials.aws.credential_file) {
    AWSConfig = loadHelperFile(config.credentials.aws.credential_file);
} else if (config.credentials.aws.access_key) {
    checkRequiredKeys(config.credentials.aws, ['secret_access_key']);
    AWSConfig = {
        accessKeyId: config.credentials.aws.access_key,
        secretAccessKey: config.credentials.aws.secret_access_key,
        sessionToken: config.credentials.aws.session_token,
        region: 'us-east-1'
    };
} else if (config.credentials.azure.credential_file) {
    AzureConfig = loadHelperFile(config.credentials.azure.credential_file);
} else if (config.credentials.azure.application_id) {
    checkRequiredKeys(config.credentials.azure, ['key_value', 'directory_id', 'subscription_id']);
    AzureConfig = {
        ApplicationID: config.credentials.azure.application_id,
        KeyValue: config.credentials.azure.key_value,
        DirectoryID: config.credentials.azure.directory_id,
        SubscriptionID: config.credentials.azure.subscription_id,
        location: 'East US'
    };
} else if (config.credentials.google.credential_file) {
    GoogleConfig = loadHelperFile(config.credentials.google.credential_file);
} else if (config.credentials.google.project) {
    checkRequiredKeys(config.credentials.google, ['client_email', 'private_key']);
    // TODO: Format?
    // GoogleConfig = {
    //     type: 'service_account',
    //     project: config.credentials.google.project,
    //     client_email: config.credentials.google.client_email,
    //     private_key: config.credentials.google.private_key,
    // };
} else if (config.credentials.oracle.credential_file) {
    OracleConfig = loadHelperFile(config.credentials.oracle.credential_file);
} else if (config.credentials.oracle.tenancy_id) {
    checkRequiredKeys(config.credentials.oracle, ['compartment_id', 'user_id', 'key_fingerprint', 'key_value']);
    OracleConfig = {
        RESTversion: '/20160918',
        tenancyId: config.credentials.oracle.tenancy_id,
        compartmentId: config.credentials.oracle.compartment_id,
        userId: config.credentials.oracle.user_id,
        keyFingerprint: config.credentials.oracle.key_fingerprint,
        keyValue: config.credentials.oracle.key_value,
        region: 'us-ashburn-1',
    };
} else if (config.credentials.github.credential_file) {
    GitHubConfig = loadHelperFile(config.credentials.github.credential_file);
} else if (config.credentials.github.token) {
    checkRequiredKeys(config.credentials.github, ['url', 'login']);
    GitHubConfig = {
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
engine(AWSConfig, AzureConfig, GitHubConfig, OracleConfig, GoogleConfig, config.settings);
