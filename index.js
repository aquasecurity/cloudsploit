#!/usr/bin/env node

const { ArgumentParser } = require('argparse');
const engine = require('./engine');


console.log(`
   _____ _                 _  _____       _       _ _   
  / ____| |               | |/ ____|     | |     (_) |  
 | |    | | ___  _   _  __| | (___  _ __ | | ___  _| |_ 
 | |    | |/ _ \\| | | |/ _\` |\\___ \\| '_ \\| |/ _ \\| | __|
 | |____| | (_) | |_| | (_| |____) | |_) | | (_) | | |_ 
  \\_____|_|\\___/ \\__,_|\\__,_|_____/| .__/|_|\\___/|_|\\__|
                                   | |                  
                                   |_|                  

  CloudSploit by Aqua Security, Ltd.
  Cloud security auditing for AWS, Azure, GCP, Oracle, and GitHub
`);

const parser = new ArgumentParser({});

parser.add_argument('--config', {
    help: 'The path to a CloudSploit config file containing cloud credentials. See config_example.js'
});

parser.add_argument('--compliance', {
    help: 'Compliance mode. Only return results applicable to the selected program.',
    choices: ['hipaa', 'cis', 'cis1', 'cis2', 'pci'],
    action: 'append'
});
parser.add_argument('--plugin', {
    help: 'A specific plugin to run. If none provided, all plugins will be run. Obtain from the exports.js file. E.g. acmValidation'
});
parser.add_argument('--govcloud', {
    help: 'AWS only. Enables GovCloud mode.',
    action: 'store_true'
});
parser.add_argument('--china', {
    help: 'AWS only. Enables AWS China mode.',
    action: 'store_true'
});
parser.add_argument('--csv', { help: 'Output: CSV file' });
parser.add_argument('--json', { help: 'Output: JSON file' });
parser.add_argument('--junit', { help: 'Output: Junit file' });
parser.add_argument('--console', {
    help: 'Console output format. Default: table',
    choices: ['none', 'text', 'table'],
    default: 'table'
});
parser.add_argument('--collection', { help: 'Output: full collection JSON as file' });
parser.add_argument('--ignore-ok', {
    help: 'Ignore passing (OK) results',
    action: 'store_true'
});
parser.add_argument('--exit-code', {
    help: 'Exits with a non-zero status code if non-passing results are found',
    action: 'store_true'
});
parser.add_argument('--skip-paginate', {
    help: 'AWS only. Skips pagination (for debugging).',
    action: 'store_false'
});
parser.add_argument('--suppress', {
    help: 'Suppress results matching the provided Regex. Format: pluginId:region:resourceId',
    action: 'append'
});
parser.add_argument('--remediate', {
    help: 'Run remediation the provided plugin',
    action: 'append'
});

let settings = parser.parse_args();
let cloudConfig = {};

settings.cloud = 'aws';

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
