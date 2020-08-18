var async = require('async');
var helpers = require('../../../helpers/aws');

function bucketIsInAccount(allBuckets, targetBucketName) {
    for (let i in allBuckets) {
        let bucket = allBuckets[i];
        if (bucket.Name === targetBucketName) {
            return true; // target bucket present in account
        }
    }
    return false; // not present in account
}

function bucketExists(err) {
    return !(err &&
        err.code &&
        err.code === 'NoSuchBucket');
}

module.exports = {
    title: 'CloudTrail Bucket Delete Policy',
    category: 'CloudTrail',
    description: 'Ensures CloudTrail logging bucket has a policy to prevent deletion of logs without an MFA token',
    more_info: 'To provide additional security, CloudTrail logging buckets should require an MFA token to delete objects',
    recommended_action: 'Enable MFA delete on the CloudTrail bucket',
    link: 'http://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete',
    apis: ['CloudTrail:describeTrails', 'S3:getBucketVersioning', 'S3:listBuckets'],
    compliance: {
        hipaa: 'An MFA delete policy helps ensure that individuals attempting to ' +
                'delete CloudTrail logs have verified their identity. HIPAA requires ' +
                'strict access controls for users modifying the environments in which ' +
                'HIPAA data is stored.'
    },
    settings: {
        ignore_bucket_not_in_account: {
            name: 'Ignore CloudTrail Buckets Not in Account',
            description: 'enable to ignore cloudtrail buckets that are not in the account',
            regex: '^(true|false)$', // string true or boolean true to enable, string false or boolean false to disable
            default: false
        },
    },

    run: function(cache, settings, callback) {
        var config = {
          ignore_bucket_not_in_account: settings.ignore_bucket_not_in_account || this.settings.ignore_bucket_not_in_account.default
        };
        if (config.ignore_bucket_not_in_account === 'false') config.ignore_bucket_not_in_account = false;
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.cloudtrail, function(region, rcb){

            var describeTrails = helpers.addSource(cache, source,
                ['cloudtrail', 'describeTrails', region]);

            if (!describeTrails) return rcb();

            if (describeTrails.err || !describeTrails.data) {
                helpers.addResult(results, 3,
                    'Unable to query for CloudTrail policy: ' + helpers.addError(describeTrails), region);
                return rcb();
            }

            if (!describeTrails.data.length) {
                helpers.addResult(results, 0, 'No S3 buckets to check', region);
                return rcb();
            }

            async.each(describeTrails.data, function(trail, cb){
                if (!trail.S3BucketName) return cb();
                // Skip CloudSploit-managed events bucket
                if (trail.S3BucketName == helpers.CLOUDSPLOIT_EVENTS_BUCKET) return cb();

                var s3Region = helpers.defaultRegion(settings);

                const listBuckets = helpers.addSource(cache, source, ['s3', 'listBuckets', s3Region]);
                if (!listBuckets) return cb(null, results, source);
                if (listBuckets.err || !listBuckets.data) {
                    helpers.addResult(results, 3, `Unable to query for S3 buckets: ${helpers.addError(listBuckets)}`);
                    return cb(null, results, source);
                }

                var getBucketVersioning = helpers.addSource(cache, source,
                    ['s3', 'getBucketVersioning', s3Region, trail.S3BucketName]);

                if (!getBucketVersioning || getBucketVersioning.err || !getBucketVersioning.data) { // data is {} if disabled. this assumes other plugin checks to see if enabled.
                    if (getBucketVersioning && !bucketExists(getBucketVersioning.err)) {
                        helpers.addResult(results, 2,
                            'Bucket: ' + trail.S3BucketName + ' does not exist' ,
                            region, 'arn:aws:s3:::' + trail.S3BucketName);

                        return cb();
                    }
                    else if (config.ignore_bucket_not_in_account && !bucketIsInAccount(listBuckets.data, trail.S3BucketName)) {
                        helpers.addResult(results, 0,
                        'Bucket: ' + trail.S3BucketName + ' is not in account',
                        region, 'arn:aws:s3:::' + trail.S3BucketName);

                        return cb();
                    } else {
                        helpers.addResult(results, 3,
                            'Error querying for bucket policy for bucket: ' + trail.S3BucketName + ': ' + helpers.addError(getBucketVersioning),
                            region, 'arn:aws:s3:::' + trail.S3BucketName);

                        return cb();
                    }
                }

                if (getBucketVersioning.data.MFADelete &&
                    getBucketVersioning.data.MFADelete === 'Enabled') {
                    helpers.addResult(results, 0,
                        'Bucket: ' + trail.S3BucketName + ' has MFA delete enabled',
                        region, 'arn:aws:s3:::' + trail.S3BucketName);
                } else {
                    helpers.addResult(results, 1,
                        'Bucket: ' + trail.S3BucketName + ' has MFA delete disabled',
                        region, 'arn:aws:s3:::' + trail.S3BucketName);
                }

                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};