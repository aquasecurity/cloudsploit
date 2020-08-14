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
    title: 'CloudTrail Bucket Private',
    category: 'CloudTrail',
    description: 'Ensures CloudTrail logging bucket is not publicly accessible',
    more_info: 'CloudTrail buckets contain large amounts of sensitive account data and should only be accessible by logged in users.',
    recommended_action: 'Set the S3 bucket access policy for all CloudTrail buckets to only allow known users to access its files.',
    link: 'http://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html',
    apis: ['CloudTrail:describeTrails', 'S3:getBucketAcl', 'S3:listBuckets'],
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
                if (!listBuckets) return rcb(null, results, source);
                if (listBuckets.err || !listBuckets.data) {
                    helpers.addResult(results, 3, `Unable to query for S3 buckets: ${helpers.addError(listBuckets)}`);
                    return rcb(null, results, source);
                }

                var getBucketAcl = helpers.addSource(cache, source,
                    ['s3', 'getBucketAcl', s3Region, trail.S3BucketName]);

                if (!getBucketAcl || getBucketAcl.err || !getBucketAcl.data) {
                    if (!bucketExists(getBucketAcl.err)) {
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
                            'Error querying for bucket policy for bucket: ' + trail.S3BucketName + ': ' + helpers.addError(getBucketAcl),
                            region, 'arn:aws:s3:::' + trail.S3BucketName);

                        return cb();
                    }
                }

                var allowsAllUsersTypes = [];

                for (var i in getBucketAcl.data.Grants) {
                    if (getBucketAcl.data.Grants[i].Grantee.Type &&
                        getBucketAcl.data.Grants[i].Grantee.Type === 'Group' &&
                        getBucketAcl.data.Grants[i].Grantee.URI &&
                        getBucketAcl.data.Grants[i].Grantee.URI.indexOf('AllUsers') > -1
                    ) {
                        allowsAllUsersTypes.push(getBucketAcl.data.Grants[i].Permission);
                    }
                }

                if (allowsAllUsersTypes.length) {
                    helpers.addResult(results, 2,
                        'Bucket: ' + trail.S3BucketName + ' allows global access to: ' + allowsAllUsersTypes.concat(', '),
                        region, 'arn:aws:s3:::' + trail.S3BucketName);
                } else {
                    helpers.addResult(results, 0,
                        'Bucket: ' + trail.S3BucketName + ' does not allow public access',
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