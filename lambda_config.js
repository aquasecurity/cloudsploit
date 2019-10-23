var AWS = require('aws-sdk');

/***
 * Finds a secret from Secrets Manager given a key and a region.
 * Expected that the value in Secrets Manager is a JSON.
 *
 * @param {String} secretManagerKey A key for where to find the secrets in secret manager.
 *
 * @param {String} region The region where the secret is stored.
 *
 * @returns A JSON object with the secret(s) found in secret manager.
 */
async function getSecret(secretManagerKey, region) {
    var secretManager = new AWS.SecretsManager({region: region});
    var data = await secretManager.getSecretValue({SecretId: secretManagerKey}).promise();
    return data.SecretString ? JSON.parse(data.SecretString) : {};
}

/**
 * Parses AWS events, currently expects either an SNS event or Cloudwatch event.
 *
 * @param event AWS Event to be parsed.
 *
 * @returns Json object containing the configuration detail from the event.
 */
function parseEvent(event) {
    var allConfigurations;

    //Expected events are SNS and Cloudwatch, could add other events here if needed.
    if(event.Records && event.Records[0].Sns) {
        console.log("---SNS Event Trigger---");
        allConfigurations = JSON.parse(event.Records[0].Sns.Message);
    } else if(event.detail) {
        console.log("---CloudWatch Event Trigger---");
        allConfigurations = event.detail;
    }
    console.assert(allConfigurations, "Configurations not found from incoming Event.");

    return allConfigurations
}

/***
 * Parses the incoming event to create configurations used for the engine.
 * Enforces that exactly 1 expected service is found in the event.
 * Any other data will be passed through untouched.
 *
 * @param {String} parsedEvent A parsed event sources from an AWS initiating event.
 * @param {String} partition The AWS partition (at current, aws, aws-cn, or aws-us-govt)
 *
 * @param {String} region The region which the Lambda is running in.
 *
 * @returns The parsed configurations with secrets in place.
 *
 * @throws Any misconfiguration will result in an error being thrown.
 */
async function getConfigurations(parsedEvent, partition) {
    console.log("Begin Parsing of Incoming Event");
    var secretPrefix = process.env.SECRET_PREFIX;
    var defaultRoleName = process.env.DEFAULT_ROLE_NAME;

    //Anything in these arrays will be required to be found in the CredentialID Secret Manager.
    var expectedServices = {
        'aws' : [],
        'azure': ["KeyValue"],
        'gcp': ["private_key"],
        'github': [],
        'oracle': ["keyValue","keyFingerprint"]
    };

    var serviceCount = 0;
    for (service in parsedEvent) {
        if(service in expectedServices) {
            console.log("---Found Service ",service.toUpperCase() ,"---");
            serviceCount++;
            if(serviceCount > 1) throw (new Error("Multiple Services in Incoming Event."));
            if(service === 'aws') {
                //If account_id in aws config, then replace it with roleArn.
                if (parsedEvent.aws.account_id) {
                    parsedEvent.aws.roleArn = ["arn", partition, "iam", "", parsedEvent.aws.account_id, "role/" + defaultRoleName].join(':');
                    delete parsedEvent.aws.account_id;
                }
            } else if(parsedEvent[service].credentialId) {
                for (config in parsedEvent[service]) {
                    if (config in expectedServices[service]) throw (new Error("Configuration passed in through event which must be in Secrets Manager."));
                }
                var secretsManagerKey = [secretPrefix, service, parsedEvent[service].credentialId].join('/');
                secret = await getSecret(secretsManagerKey); // eslint-disable-line  no-await-in-loop
                delete parsedEvent[service].credentialId;
                Object.assign(parsedEvent[service], secret);
            }
        }
    }

    if(serviceCount === 0) throw (new Error("No services provided or provided services are malformed in Incoming Event."));
    return parsedEvent;
}

/***
 * Uses STS to obtain credentials for AWS Config.
 * It is expected that AWSConfig is only obtainable via assuming a role.
 *
 * @param {String} roleArn The ARN for the role to get credentials for.
 *
 * @param {String} region The region where the credentials are located.
 *
 * @param {String} [externalID] The externalID used for role assumption.
 *
 * @returns Promise containing the requested AWS Configuration.
 *
 * @throws If roleArn is not defined, rejects with an error.
 */
function getCredentials(roleArn, region, externalId) {
    console.log("---Getting Credentials for AWS Configuration---");
    if(!roleArn) {
        throw new Error("roleArn is not defined from incoming event.");
    }
    var STSParams = {
        RoleArn: roleArn
    };
    if(externalId) {
        STSParams.ExternalId = externalId
    };
    var creds = new AWS.ChainableTemporaryCredentials({params:STSParams});

    var config = {
        'accessKeyId' : creds.service.config.credentials.accessKeyId,
        'secretAccessKey' : creds.service.config.credentials.secretAccessKey,
        'sessionToken' : creds.service.config.credentials.sessionToken,
        'region': region
    };
    return config;
}

module.exports = {getConfigurations, parseEvent, getCredentials}