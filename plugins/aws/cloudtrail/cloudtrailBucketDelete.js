var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudTrail Bucket Delete Policy',
    category: 'S3',
    domain: 'Compliance',
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
        whitelist_ct_deleted_buckets: {
            name: 'Whitelist Cloud Trail Deleted Buckets',
            description: 'All buckets against this regex will be whitelisted',
            regex: '^.*$',
            default: '',
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            whitelist_ct_deleted_buckets: settings.whitelist_ct_deleted_buckets ||  this.settings.whitelist_ct_deleted_buckets.default
        };
        var regBucket;
        if (config.whitelist_ct_deleted_buckets.length) regBucket= new RegExp(config.whitelist_ct_deleted_buckets); 
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var defaultRegion = helpers.defaultRegion(settings);

        var listBuckets = helpers.addSource(cache, source,
            ['s3', 'listBuckets', defaultRegion]);

        if (!listBuckets || listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3,
                'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
            return callback(null, results, source);
        }

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
                if (!trail.S3BucketName || (trail.HomeRegion && trail.HomeRegion.toLowerCase() !== region)) return cb();
                // Skip CloudSploit-managed events bucket
                if (trail.S3BucketName == helpers.CLOUDSPLOIT_EVENTS_BUCKET) return cb();

                if (regBucket && regBucket.test(trail.S3BucketName)) {
                    helpers.addResult(results, 0, 
                        'Bucket is whitelisted', region, 'arn:aws:s3:::'+trail.S3BucketName);
                    return cb();
                }

                if (!listBuckets.data.find(bucket => bucket.Name == trail.S3BucketName)) {
                    helpers.addResult(results, 2,
                        'Unable to locate S3 bucket, it may have been deleted',
                        region, 'arn:aws:s3:::' + trail.S3BucketName);
                    return cb(); 
                }

                var s3Region = helpers.defaultRegion(settings);

                var getBucketVersioning = helpers.addSource(cache, source,
                    ['s3', 'getBucketVersioning', s3Region, trail.S3BucketName]);

                if (!getBucketVersioning || getBucketVersioning.err || !getBucketVersioning.data) {
                    helpers.addResult(results, 3,
                        'Error querying for bucket policy for bucket: ' + trail.S3BucketName + ': ' + helpers.addError(getBucketVersioning),
                        region, 'arn:aws:s3:::' + trail.S3BucketName);

                    return cb();
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