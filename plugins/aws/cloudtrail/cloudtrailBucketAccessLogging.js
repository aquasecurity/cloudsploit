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
    title: 'CloudTrail Bucket Access Logging',
    category: 'CloudTrail',
    description: 'Ensures CloudTrail logging bucket has access logging enabled to detect tampering of log files',
    more_info: 'CloudTrail buckets should utilize access logging for an additional layer of auditing. If the log files are deleted or modified in any way, the additional access logs can help determine who made the changes.',
    recommended_action: 'Enable access logging on the CloudTrail bucket from the S3 console',
    link: 'http://docs.aws.amazon.com/AmazonS3/latest/UG/ManagingBucketLogging.html',
    apis: ['CloudTrail:describeTrails', 'S3:getBucketLogging', 'S3:listBuckets'],
    compliance: {
        hipaa: 'Access logging for CloudTrail helps ensure strict integrity controls, ' +
                'verifying that the audit logs for the AWS environment are not modified.',
        pci: 'PCI requires tracking and monitoring of all access to environments ' +
             'in which cardholder data is present. CloudTrail bucket access logging ' +
             'helps audit the bucket in which these logs are stored.'
    },
    settings: {
        ignore_bucket_not_in_account: {
            name: 'Ignore CloudTrail Buckets Not in Account',
            description: 'enable to ignore cloudtrail buckets that are not in the account',
            regex: '^(true|false)$', // string true or boolean true to enable, string false or boolean false to disable
            default: true
        },
    },

    run: function(cache, settings, callback) {
        var config = {
          ignore_bucket_not_in_account: settings.ignore_bucket_not_in_account || this.settings.ignore_bucket_not_in_account.default
        };
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
                if (!listBuckets) return rcb(null, results, source);
                if (listBuckets.err || !listBuckets.data) {
                    helpers.addResult(results, 3, `Unable to query for S3 buckets: ${helpers.addError(listBuckets)}`);
                    return rcb(null, results, source);
                }

                var getBucketLogging = helpers.addSource(cache, source,
                    ['s3', 'getBucketLogging', s3Region, trail.S3BucketName]);

                if (!getBucketLogging || getBucketLogging.err || !getBucketLogging.data) {
                    if (!bucketExists(getBucketLogging.err)) {
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
                            'Error querying for bucket policy for bucket: ' + trail.S3BucketName + ': ' + helpers.addError(getBucketLogging),
                            region, 'arn:aws:s3:::' + trail.S3BucketName);

                        return cb();
                    }
                }

                if (getBucketLogging &&
                    getBucketLogging.data &&
                    getBucketLogging.data.LoggingEnabled) {
                    helpers.addResult(results, 0,
                        'Bucket: ' + trail.S3BucketName + ' has S3 access logs enabled',
                        region, 'arn:aws:s3:::' + trail.S3BucketName);
                } else {
                    helpers.addResult(results, 1,
                        'Bucket: ' + trail.S3BucketName + ' has S3 access logs disabled',
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