var AWS = require('aws-sdk');
var engine = require('./engine.js');
var output = require('./postprocess/json_output.js');
const Promise = require('bluebird');

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

/***
 * Parses the incoming event to create configurations used for the engine.
 * Enforces that exactly 1 expected service is found in the event.
 * Any other data will be passed through untouched.
 *
 * @param {String} event The initializing event for the lambda.
 *
 * @param {String} partition The AWS partition (at current, aws, aws-cn, or aws-us-govt)
 *
 * @param {String} region The region which the Lambda is running in.
 *
 * @returns The parsed configurations with secrets in place.
 *
 * @throws Any misconfiguration will result in an error being thrown.
 */
async function parseInput(event, partition, region) {
    console.log("--Begin Parsing of Incoming Event--");
    var allConfigurations;
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

    //Expected events are SNS and Cloudwatch, could add other events here if needed.
    if(event.Records && event.Records[0].Sns) {
        console.log("---SNS Event Trigger---");
        allConfigurations = JSON.parse(event.Records[0].Sns.Message);
    } else if(event.detail) {
        console.log("---CloudWatch Event Trigger---");
        allConfigurations = event.detail;
    }
    console.assert(allConfigurations, "Configurations not found from incoming Event.");

    var serviceCount = 0;
    for (service in allConfigurations) {
        if(service in expectedServices) {
            console.log("---Found Service ",service.toUpperCase() ,"---");
            serviceCount++;
            if(serviceCount > 1) throw (new Error("Multiple Services in Incoming Event."));
            if(service === 'aws') {
                //If account_id in aws config, then replace it with roleArn.
                if (allConfigurations.aws.account_id) {
                    allConfigurations.aws.roleArn = ["arn",partition,"iam","",allConfigurations.aws.account_id,("role/" + defaultRoleName)].join(':');
                    delete allConfigurations.aws.account_id;
                }
            } else if(allConfigurations[service].credentialId) {
                for (config in allConfigurations[service]) {
                    if (config in expectedServices[service]) throw (new Error("Configuration passed in through event which must be in Secrets Manager."));
                }
                var secretsManagerKey = [secretPrefix, service, allConfigurations[service].credentialId].join('/');
                secret = await getSecret(secretsManagerKey, region);
                delete allConfigurations[service].credentialId;
                Object.assign(allConfigurations[service], secret);
            }
        }
    }

    if(serviceCount === 0) throw (new Error("No services provided or provided services are malformed in Incoming Event."));
    return allConfigurations;
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

/***
 * Writes the output to S3, it writes two files.
 * First file is a file with the current date the second file is 'latest'. Both json files.
 *
 * @param {String} bucket The bucket where files will be written to.
 *
 * @param {JSON} resultsToWrite The results to be persisted in S3.
 *
 * @param {String} [prefix] The prefix for the file in the assocaited bucket.
 *
 * @returns a list or promises for write to S3.
 */
async function writeToS3(bucket, resultsToWrite, prefix) {
    var s3 = new AWS.S3({apiVersion: 'latest'});
    var bucketPrefix = prefix || "";
    if(bucket && resultsToWrite) {
        console.log("-Writing Output to S3-");
        var dt = new Date();
        var objectName = [dt.getFullYear(), dt.getMonth() + 1, dt.getDate() + '.json'].join( '-' );
        var key = [bucketPrefix, objectName].join('/');
        var latestKey = [bucketPrefix, "latest.json"].join('/');
        var results = JSON.stringify(resultsToWrite, null, 2);

        var promises = [];
        promises.push(s3.putObject({Bucket: bucket, Key: key, Body: results}).promise());
        promises.push(s3.putObject({Bucket: bucket, Key: latestKey, Body: results}).promise());

        return promises;
    }
}

exports.handler = async function(event, context) {
    console.log("-Begin CloudSploit Lambda-");
    try {
        //Object Initialization//
        var partition = context.invokedFunctionArn.split(':')[1];
        var region = context.invokedFunctionArn.split(':')[3];
        var configurations = await parseInput(event, partition, region);
        var outputHandler = output.create();

        //Settings Configuration//
        console.log("--Configuring Settings--");
        var settings = configurations.settings || {};
        settings.china = partition === 'aws-cn';
        settings.govcloud = partition === 'aws-us-gov';
        settings.paginate = settings.paginate || true;
        settings.debugTime = settings.debugTime || false;

        //TODO: consider supporting supression based on incoming settings.

        //Config Gathering//
        console.log("--Gathering Configurations--");
        var AWSConfig = configurations.aws.roleArn ? getCredentials(configurations.aws.roleArn, region, configurations.aws.externalId) : null;
        var AzureConfig = configurations.azure || null;
        var GoogleConfig = configurations.gcp || null;
        var GitHubConfig = configurations.github || null;
        var OracleConfig = configurations.oracle || null;
    } catch(err) {
        //This is mainly here in the case of implementing more robust error handling.
        console.log(err);
        throw(err);
    }

    //Run Primary Cloudspoit Engine//
    console.log("-Begin Calling Main Engine-")
    var enginePromise = Promise.fromCallback((callback) => {
        engine(AWSConfig, AzureConfig, GitHubConfig, OracleConfig, GoogleConfig, settings, outputHandler, callback);
    })

    return enginePromise.then((collectionData) => {
        var resultCollector = {};
        resultCollector.collectionData = collectionData;
        resultCollector.ResultsData = outputHandler.getOutput();
        console.assert(resultCollector.collectionData, "No Collection Data found.");
        console.assert(resultCollector.ResultsData, "No Results Data found.");

        var outputPromises = writeToS3(process.env.RESULT_BUCKET, resultCollector, process.env.RESULT_PREFIX);
        return Promise.all(outputPromises);
    }).catch((error)=> {
        console.log(error);
    });
}