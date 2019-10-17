var AWS = require('aws-sdk');
var engine = require('./engine');
var output = require('./postprocess/json_output.js')

async function getSecret(secretManagerKey, region) {
    var secretManager = new AWS.SecretsManager({region: region});

    var data = await secretManager.getSecretValue({SecretId: secretManagerKey}).promise();
    return data.SecretString ? JSON.parse(data.SecretString) : {}
}

async function parseInput(event, partition, region) {
    var eventJSON = JSON.parse(event);
    var allConfigurations;
    var secretPrefix = process.env.SECRET_PREFIX;
    var defaultRoleName = process.env.DEFAULT_ROLE_NAME;
    var configurations = ['aws', 'azure', 'gcp', 'github', 'oracle']

    if(eventJSON.Records && eventJSON.Records[0].Sns) {
        allConfigurations = eventJSON.Records[0].Sns.Message;
    } else if(eventJSON.detail) {
        allConfigurations = eventJSON.detail;
    }

    //TODO: Consider enforcing certain things to be secrets. 
    for (service in allConfigurations) {
        if(service in configurations) {
            if(service == 'aws') {
                if(allConfigurations.aws.roleArn ) {
                    allConfigurations.awsSts.roleArn = allConfigurations.aws.roleArn;
                    delete allConfigurations.aws
                    continue;
                } else if (allConfigurations.aws.account_id) {
                    allConfigurations.awsSts.roleArn = ["arn",partition,"iam","",allConfigurations.aws.account_id,("role/" + defaultRoleName)].join(':');
                    delete allConfigurations.aws
                    continue;
                }
            }
            
            if(allConfigurations[service].credentialId) {
                var secretsManagerKey = [secretPrefix, service, allConfigurations[service].credentialId].join('/');
                secret = await getSecret(secretsManagerKey, region) 
                delete allConfigurations[service].credentialId
                Object.assign(allConfigurations[service], secret)
                //Do we validate or do we let those issues fall through to cloudspoit? (I assume they validate configs somewhere in their implementation?)
            }
        }
    }

    return allConfigurations
}

//TODO: Promise for chainable...?
async function getCredentials(roleArn) {
    AWS.config.credentials = new AWS.ChainableTemporaryCredentials({params:{RoleArn: roleArn}})
    
    config = {
        'accessKeyId' : AWS.config.credentials.AccessKeyId,
        'secretAccessKey' : AWS.config.credentials.SecretAccessKey,
        'sessionToken' : AWS.config.credentials.SessionToken
    }
    return config;
}

async function writeToS3(s3Config, resultsToWrite) {
    var s3 = new AWS.S3({apiVersion: 'latest'});
    if(s3Config.key && s3Config.bucket) {
        var dt = new Date();
        var objectName = [ dt.getFullYear(), dt.getMonth() + 1, dt.getDate() + '.json' ].join( '-' );
        var key = [ s3Config.key, objectName ].join( '/' );
        var latestKey = [ s3Config.key, "latest.json" ].join( '/' );
        var results = JSON.stringify(resultsToWrite, null, 2);

        await s3.putObject( { Bucket: s3Config.bucket, Key: key, Body: results }).promise();
        await s3.putObject( { Bucket: s3Config.bucket, Key: latestKey, Body: results }).promise();
    }
}

exports.handler = async function(event, context) {
    //TODO: Logging
    var AWSConfig;
    var AzureConfig;
    var GitHubConfig;
    var OracleConfig;
    var GoogleConfig;
    var bucket = process.env.RESULT_BUCKET;
    var key = process.env.RESULT_PREFIX;
    var partition = context.invokedFunctionArn.split(':')[1];
    var region = context.invokedFunctionArn.split(':')[3];
    var configurations = await parseInput(event, partition, region);
    
    //////////////////////////
    //Settings Configuration//
    //////////////////////////
    var settings = configurations.settings ? configurations.settings : {};
    settings.china = partition=='aws-cn';
    settings.govcloud = partition=='aws-us-gov';
    settings.paginate = settings.paginate ? settings.paginate : true;
    settings.debugTime = settings.debugTime ? settings.debugTime : false;

    var outputHandler = output.create()

    //TODO: return error if more than one configuration is passed in. 
    if(configurations.awsSts) {
        AWSConfig = await getCredentials(configurations.awsSts.roleArn)
    } else if(configurations.azure) {
        AzureConfig = configurations.azure;
    } else if(configurations.gcp) {
        GoogleConfig = configurations.gcp;
    } else if(configurations.github) {
        GitHubConfig = configurations.github;
    } else if(configurations.oracle) {
        OracleConfig = configurations.oracle;
    }

    engine(AWSConfig, AzureConfig, GitHubConfig, OracleConfig, GoogleConfig, settings, outputHandler, (collectionData) => {
        var resultCollector = {}
        resultCollector.collectionData = collectionData;
        resultCollector.ResultsData = outputHandler.outputCollector;
        await writeToS3({"key": key, "bucket": bucket}, resultCollector)
    });
}