var AWS = require('aws-sdk');
var secretManager = new AWS.SecretsManager();
var engine = require('./engine.js');
var jsonOutput = require('./postprocess/json_output.js');
var configs = require('./lambda_config.js')
const Promise = require('bluebird');

/***
 * Writes the output to S3, it writes two files.
 * First file is a file with the current date the second file is 'latest'. Both json files.
 *
 * @param {String} bucket The bucket where files will be written to.
 * @param {JSON} resultsToWrite The results to be persisted in S3.
 * @param {String} [prefix] The prefix for the file in the assocaited bucket.
 *
 * @returns a list or promises for write to S3.
 */
async function writeToS3(bucket, resultsToWrite, prefix) {
    var s3 = new AWS.S3({apiVersion: 'latest'});
    var bucketPrefix = prefix || "";
    if (bucket && resultsToWrite) {
        console.log("Writing Output to S3");
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
    console.log("EVENT:", JSON.stringify(event));
    try {
        //Object Initialization//
        var partition = context.invokedFunctionArn.split(':')[1];

        var configurations = await configs.getConfigurations(configs.parseEvent(event), partition);
        var outputHandler = jsonOutput.create();

        //Settings Configuration//
        console.log("Configuring Settings");
        var settings = configurations.settings || {};
        settings.china = partition === 'aws-cn';
        settings.govcloud = partition === 'aws-us-gov';
        settings.paginate = settings.paginate || true;
        settings.debugTime = settings.debugTime || false;

        //Config Gathering//
        console.log("Gathering Configurations");
        var AWSConfig = configurations.aws.roleArn ? configs.getCredentials(configurations.aws.roleArn, configurations.aws.externalId) : null;
        var AzureConfig = configurations.azure || null;
        var GoogleConfig = configurations.gcp || null;
        var GitHubConfig = configurations.github || null;
        var OracleConfig = configurations.oracle || null;

        //Run Primary Cloudspoit Engine//
        console.log("Begin Calling Main Engine")
        var enginePromise = Promise.fromCallback((callback) => {
            engine(AWSConfig, AzureConfig, GitHubConfig, OracleConfig, GoogleConfig, settings, outputHandler, callback);
        })

        const collectionData = await enginePromise;
        var resultCollector = {};
        resultCollector.collectionData = collectionData;
        resultCollector.ResultsData = outputHandler.getOutput();
        console.assert(resultCollector.collectionData, "No Collection Data found.");
        console.assert(resultCollector.ResultsData, "No Results Data found.");
        var outputPromises = writeToS3(process.env.RESULT_BUCKET, resultCollector, process.env.RESULT_PREFIX);
        await Promise.all(outputPromises);
        return 'Ok';
    } catch(err) {
        console.log(err);
        throw(err);
    }

}