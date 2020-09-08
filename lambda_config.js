var AWS = require('aws-sdk');
var secretManager = new AWS.SecretsManager();

/***
 * Finds a secret from Secrets Manager given a key and a region.
 * Expected that the value in Secrets Manager is a JSON.
 *
 * @param {String} secretManagerKey A key for where to find the secrets in secret manager.
 *
 * @returns A JSON object with the secret(s) found in secret manager.
 */
async function getSecret(secretManagerKey) {
    var data = await secretManager.getSecretValue({SecretId: secretManagerKey}).promise();
    return data.SecretString ? JSON.parse(data.SecretString) : {};
}

/**
 * Parses AWS events, currently expects either an SNS event or Cloudwatch event.
 *
 * @param event AWS Event to be parsed.
 * @returns Json object containing the configuration detail from the event.
 */
function parseEvent(event) {
    var allConfigurations;

    //Expected events are SNS and Cloudwatch, could add other events here if needed.
    if(event.Records && event.Records[0].Sns) {
        console.log('SNS Event Trigger');
        allConfigurations = JSON.parse(event.Records[0].Sns.Message);
    } else if(event.detail) {
        console.log('CloudWatch Event Trigger');
        allConfigurations = event.detail;
    } else {
        allConfigurations = event;
    }
    // console.assert(allConfigurations, "Configurations not found from incoming Event.");

    return allConfigurations;
}

/***
 * Parses the incoming event to create configurations used for the engine.
 * Enforces that exactly 1 expected service is found in the event.
 * Any other data will be passed through untouched.
 *
 * @param {String} parsedEvent A parsed event sources from an AWS initiating event.
 * @param {String} partition The AWS partition (at current, aws, aws-cn, or aws-us-govt)
 * @returns The parsed configurations with secrets in place.
 *
 * @throws Any misconfiguration will result in an error being thrown.
 */
async function getCloudConfig(parsedEvent, partition) {
    console.log('Begin Parsing of Incoming Event');
    var secretPrefix = process.env.SECRET_PREFIX;
    var defaultRoleName = process.env.DEFAULT_ROLE_NAME;

    // Anything in these arrays will be required to be found in the CredentialID Secret Manager.
    var clouds = ['aws', 'azure', 'gcp', 'github', 'oracle'];

    var disallowedKeysByServices = {
        'aws' : [],
        'azure': ['KeyValue'],
        'gcp': ['private_key'],
        'github': [],
        'oracle': ['keyValue', 'keyFingerprint']
    };
    var cloud = parsedEvent.cloud;
    var cloudConfig = parsedEvent.cloudConfig;

    if (!clouds.find(c => c === cloud)) {
        throw new Error('Invalid cloud specified');
    }

    disallowedKeysByServices[cloud].forEach((config) => {
        if (config in cloudConfig) throw (new Error('Configuration passed in through event which must be in Secrets Manager.'));
    });
    if (cloud === 'aws') {
        // If account_id in aws config, then replace it with roleArn.
        if (cloudConfig.account_id) {
            cloudConfig.roleArn = ['arn', partition, 'iam', '', cloudConfig.account_id, 'role/' + defaultRoleName].join(':');
            delete cloudConfig.account_id;
        }
    } else if (cloudConfig.credentialId) {
        var secretsManagerKey = [secretPrefix, cloud, cloudConfig.credentialId].join('/');
        var secret = await getSecret(secretsManagerKey); // eslint-disable-line  no-await-in-loop
        delete cloudConfig.credentialId;
        Object.assign(cloudConfig, secret);
    }

    return [cloud, cloudConfig];
}

/***
 * Uses STS to obtain credentials for AWS Config.
 * It is expected that AWSConfig is only obtainable via assuming a role.
 *
 * @param {String} roleArn The ARN for the role to get credentials for.
 * @param {String} [externalID] The externalID used for role assumption.
 * @returns AWS Configuration for cloudsploit engine.
 *
 */

async function getCredentials(roleArn, externalId) {
    console.log('Getting Credentials for AWS Configuration');
    if(!roleArn) {
        throw new Error('roleArn is not defined from incoming event.');
    }
    var STSParams = {
        RoleArn: roleArn,
        ExternalId: externalId
    };
    let credentials = new AWS.ChainableTemporaryCredentials({ params: STSParams });

    return credentials.getPromise().then(() => {
        return { credentials };
    });
}

module.exports = {getCloudConfig, parseEvent, getCredentials};
