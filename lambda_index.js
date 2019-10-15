var AWS = require('aws-sdk');
var engine = require('./engine');

function getSecret(secretManagerKey, region) {
    var secretManager = new AWS.SecretsManager({region: region});
    var secret;
    secretManager.getSecretValue({SecretId: secretManagerKey}, function(err, data) {
        if (err) {
            //handle error
        } else {
            if ('SecretString' in data) {
                secret = data.SecretString;
            } else {
                let buff = new Buffer(data.SecretBinary, 'base64');
                secret = buff.toString('ascii');
            }
        }
    });
    return secret;
}

function parseInput(event, context) {
    var eventJSON = JSON.parse(event);
    var incomingConfig;
    var secretPrefix = process.env.SECRET_PREFIX;
    var defaultRoleName = process.env.DEFAULT_ROLE_NAME;
    var output = {};

    var secrets = {
        'aws' : [],
        'azure' : [],
        'gcp' : [],
        'github' : [],
        'oracle' : []
    };

    if('Records' in eventJSON && 'Sns' in eventJSON.Records[0]) {
        incomingConfig = eventJSON.Records[0].Sns.Message;
    } else if('detail' in eventJSON && 'aws' in eventJSON.detail) {
        incomingConfig = eventJSON.detail;
    }

    for (service in incomingConfig) {
        output[service] = {};
        if(service == 'aws') {
            if('externalId' in incomingConfig.aws) {
                output.awsSts.externalId = incomingConfig.aws.externalId;
            }
            
            //If someone simply passes in configuration information for AWS identical to AWSConfig with info in secrets manager, then this will be excluded. 
            if('roleArn' in incomingConfig.aws && incomingConfig.aws.roleArn ) {
                output.awsSts.roleArn = incomingConfig.aws.roleArn;
                continue;
            } else if ('account_id' in incomingConfig.aws) {
                var partition = context.invokedFunctionArn.split(':')[1];
                output.awsSts.roleArn = ["arn",partition,"iam","",incomingConfig.aws.account_id,("role/" + defaultRoleName)].join(':');
                continue;
            }
        }
        if(service in secrets) {
            for(config in service) {
                if (config in secrets[service]) {
                    //is it value found at secret location or the key??
                    //var secretsManagerKey = [secretPrefix, service, config].join('/');
                    var secretsManagerKey = [secretPrefix, service, incomingConfig[service][config]].join('/');
                    //making an assumption that secrets are in the initiating account and that theyre in the same region as the lambda. 
                    var foundSecret = getSecret(secretsManagerKey,context.invokedFunctionArn.split(':')[3]); 
                    output[service][config] = foundSecret;
                } else {
                    output[service][config] = incomingConfig[service][config];
                }
            }
        } else {
            output[service] = incomingConfig[service];
        }
    }

    return output;
}

exports.handler = (event, context, callback) => {
    //TODO: Logging
    var AWSConfig;
    var AzureConfig;
    var GitHubConfig;
    var OracleConfig;
    var GoogleConfig;
    var settings = {};
    var bucket = process.env.RESULT_BUCKET;
    var key = process.env.RESULT_PREFIX;

    var configurations = parseInput(event, context);
    if ('settings' in configurations) {
        settings = configurations.settings;
    }
    if(!s3Config in settings) {
        settings.s3Config = {"key": key, "bucket": bucket}
    }

    /*  This is just a possible way to include alternate configurations in the main lambda that invokes another role. 
        if('aws' in configurations) {
            AWSConfig = configurations.aws
        }
        if('azure' in configurations) {
            AzureConfig = configurations.azure
        }
        if('gcp' in configurations) {
            GoogleConfig = configurations.gcp
        }
        if('github' in configurations) {
            GitHubConfig = configurations.github
        }
        if('oracle' in configurations) {
            OracleConfig = configurations.oracle
        }
    */

    if ('awsSts' in configurations) {
        var roleArn = configurations.awsSts.roleArn;
        var externalId = configurations.awsSts.externalId;

        var sts = new AWS.STS({apiVersion: 'latest'});
        var params = {
            'RoleArn': roleArn,
            'RoleSessionName': 'cloudSploit',
            'DurationSeconds': 900
        };
        if(externalId) {
            params.ExternalId = externalId;
        }

        sts.assumeRole(params, function(err, data){ 
            if (err) {
                //handle error
            } else {
                AWSConfig = { 
                    'accessKeyId' : data.Credentials.AccessKeyId,
                    'secretAccessKey' : data.Credentials.SecretAccessKey,
                    'sessionToken' : data.Credentials.SessionToken,
                    //'region' : ''
                };
                engine(AWSConfig, AzureConfig, GitHubConfig, OracleConfig, GoogleConfig, settings);
                //where should I handle output? updates engine.js with possible settings ammendment to include bucket info?
            }
        });
    } else {
        //technically with this implementation, we could run against all the others here - but we chose only one. So i am implmenting it that way. 
        if('aws' in configurations) {
            AWSConfig = configurations.aws;
        } else if('azure' in configurations) {
            AzureConfig = configurations.azure;
        } else if('gcp' in configurations) {
            GoogleConfig = configurations.gcp;
        } else if('github' in configurations) {
            GitHubConfig = configurations.github;
        } else if('oracle' in configurations) {
            OracleConfig = configurations.oracle;
        }
        engine(AWSConfig, AzureConfig, GitHubConfig, OracleConfig, GoogleConfig, settings);
    }
}