var AWS = require('aws-sdk');
var engine = require('./engine.js');
var output = require('./postprocess/output.js');
var configs = require('./lambda_config.js');
var util = require('util');
var promisifiedEngine = util.promisify(engine);

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
    var bucketPrefix = templatePrefix ? `${templatePrefix}/` : '';
    bucketPrefix = s3Prefix ? `${bucketPrefix}${s3Prefix}/` : bucketPrefix;
    // require('fs').writeFileSync('runresults.json', JSON.stringify(resultsToWrite, null, 2));
    if (bucket && resultsToWrite) {
        console.log('Writing Output to S3');
        var dt = new Date();
        var objectName = [dt.getFullYear(), dt.getMonth() + 1, dt.getDate() + '.json'].join( '-' );
        var key = bucketPrefix + objectName;
        var latestKey = bucketPrefix + 'latest.json';
        var results = JSON.stringify(resultsToWrite, null, 2);
        console.log(`Writing results to s3://${bucket}/${key}`);
        console.log(`Writing results to s3://${bucket}/${latestKey}`);
        var promises = [
            s3.putObject({Bucket: bucket, Key: latestKey, Body: results}).promise(),
            s3.putObject({Bucket: bucket, Key: key, Body: results}).promise()
        ];

        return Promise.all(promises);
    }
    return [];
}

// "memoryStream" to get outputs instead of using a file stream
class MemoryStream {
    constructor() {
        this.data = '';
    }
    write(chunk) {
        this.data += chunk;
    }
    end() {}
}

exports.handler = async function(event, context) {
    console.log('EVENT:', JSON.stringify(event));
    try {
        //Object Initialization//
        var partition = context.invokedFunctionArn.split(':')[1];
        var parsedEvent = configs.parseEvent(event);
        var [cloud, cloudConfig] = await configs.getCloudConfig(event, partition);

        var jsonOutput = new MemoryStream();
        var collectionOutput = new MemoryStream();
        var outputHandler = output.multiplexer([output.createJson(jsonOutput)], [output.createCollection(collectionOutput)], false);
        //Settings Configuration//
        console.log('Configuring Settings');
        var settings = parsedEvent.settings || {};
        settings.china = partition === 'aws-cn';
        settings.govcloud = partition === 'aws-us-gov';
        settings.paginate = settings.paginate || true;
        settings.debugTime = settings.debugTime || false;
        settings.cloud = cloud;
        //Config Gathering//
        console.log('Gathering Configurations');

        if (cloud === 'aws') {
            cloudConfig = cloudConfig.roleArn ? await configs.getCredentials(cloudConfig.roleArn, cloudConfig.externalId) : null;
        }

        //Run Primary Cloudspoit Engine//
        console.log('Begin Calling Main Engine');

        var enginePromise = promisifiedEngine(cloudConfig, settings, outputHandler);

        await enginePromise;
        var results = {
            collectionData: {
                [cloud]: JSON.parse(collectionOutput.data),
            },
            resultsData: JSON.parse(jsonOutput.data)
        };

        console.assert(results.collectionData, 'No Collection Data found.');
        console.assert(results.resultsData, 'No Results Data found.');
        await writeToS3(process.env.RESULT_BUCKET, results, process.env.RESULT_PREFIX, parsedEvent.s3Prefix);
        return 'Ok';
    } catch(err) {
        // Just log the error and re-throw so we have a lambda error metric
        console.log(err);
        throw(err);
    }
};
