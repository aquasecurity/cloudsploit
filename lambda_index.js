var AWS = require('aws-sdk');
var engine = require('./engine.js');
var jsonOutput = require('./postprocess/json_output.js');
var configs = require('./lambda_config.js')
const Promise = require('bluebird');

/***
 * Writes the output to S3, it writes two files.
 * First file is a file with the current date the second file is 'latest'. Both json files.
 * The full path looks like this where two files are created, one with latest and one with the date:
 * s3://bucket/[templateprefix/][s3Prefix/][date && latest].json
 *
 * @param {String} bucket The bucket where files will be written to.
 * @param {JSON} resultsToWrite The results to be persisted in S3.
 * @param {String} [templatePrefix] The prefix for the file in the associated bucket passed in through environment information.
 * @param {String} [s3Prefix] The prefix for the file in the associated bucket passed in through the event.
 *
 * @returns a list or promises for write to S3.
 */
async function writeToS3(bucket, resultsToWrite, templatePrefix, s3Prefix) {
    var s3 = new AWS.S3({apiVersion: 'latest'});
    var bucketPrefix = templatePrefix ? (`${templatePrefix}/`) : "";
    bucketPrefix = s3Prefix ? (`${bucketPrefix}${s3Prefix}/`) : bucketPrefix;
    if (bucket && resultsToWrite) {
        console.log("Writing Output to S3");
        var dt = new Date();
        var objectName = [dt.getFullYear(), dt.getMonth() + 1, dt.getDate() + '.json'].join( '-' );
        var key = bucketPrefix + objectName;
        var latestKey = bucketPrefix + "latest.json";
        var results = JSON.stringify(resultsToWrite, null, 2);
        console.log(`Files written to:`)
        console.log(`s3://${bucket}/${key}`)
        console.log(`s3://${bucket}/${latestKey}`)

        var promises = [
            s3.putObject({Bucket: bucket, Key: latestKey, Body: results}).promise(),
            s3.putObject({Bucket: bucket, Key: key, Body: results}).promise()
        ];

        return Promise.all(promises);
    }
    return []
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
        var AWSConfig = configurations.aws.roleArn ? await configs.getCredentials(configurations.aws.roleArn, configurations.aws.externalId) : null;
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
        await writeToS3(process.env.RESULT_BUCKET, resultCollector, process.env.RESULT_PREFIX, configurations.s3Prefix);
        return 'Ok';
    } catch(err) {
        // Just log the error and re-throw so we have a lambda error metric
        console.log(err);
        throw(err);
    }
}