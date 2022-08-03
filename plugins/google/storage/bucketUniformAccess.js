var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Bucket Uniform Level Access',
    category: 'Storage',
    domain: 'Storage',
    description: 'Ensures that uniform level access is enabled on storage buckets.',
    more_info: 'Uniform level access for buckets can be used for managing access in a simple way. It enables us to use other security features like IAM conditions.',
    link: 'https://cloud.google.com/storage/docs/uniform-bucket-level-access#should-you-use',
    recommended_action: 'Make sure that storage buckets have uniform level access enabled',
    apis: ['buckets:list'],
    remediation_min_version: '202207281836',
    remediation_description: 'Unfiorm Level Access will be enabled on all storage buckets',
    apis_remediate: ['buckets:list'],
    actions: {remediate:['storage.buckets.update'], rollback:['storage.buckets.update']},
    permissions: {remediate: ['storage.buckets.setIamPolicy', 'storage.buckets.update'], rollback: ['storage.buckets.setIamPolicy','storage.buckets.update']},
    realtime_triggers: ['storage.buckets.update', 'storage.buckets.create'],
  
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.buckets, function(region, rcb){
            let buckets = helpers.addSource(
                cache, source, ['buckets', 'list', region]);

            if (!buckets) return rcb();

            if (buckets.err || !buckets.data) {
                helpers.addResult(results, 3, 'Unable to query storage buckets: ' + helpers.addError(buckets), region);
                return rcb();
            }

            if (!buckets.data.length) {
                helpers.addResult(results, 0, 'No storage buckets found', region);
                return rcb();
            }

            var bucketFound = false;
            buckets.data.forEach(bucket => {
                if (bucket.name) {
                    let resource = helpers.createResourceName('b', bucket.name);
                    bucketFound = true;
                    if (bucket.iamConfiguration &&
                        bucket.iamConfiguration.uniformBucketLevelAccess && 
                        bucket.iamConfiguration.uniformBucketLevelAccess.enabled) {
                        helpers.addResult(results, 0, 'Bucket has uniform bucket level access enabled', region, resource);
                    } else {
                        helpers.addResult(results, 2, 'Bucket does not have uniform bucket level access enabled', region, resource);
                    }
                }

                if (!bucketFound) {
                    helpers.addResult(results, 0, 'No storage buckets found', region);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;

        // inputs specific to the plugin
        var pluginName = 'bucketUniformAccess';
        var baseUrl = 'https://storage.googleapis.com/storage/v1/{resource}';
        var method = 'PUT';
        var putCall = this.actions.remediate;

        // create the params necessary for the remediation
        var body = {
            iamConfiguration: {
                uniformBucketLevelAccess: {
                    enabled: true
                }
            }
        };
        // logging
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'UniformBucketLevelAccess': 'Disabled'
        };

        helpers.remediatePlugin(config, method, body, baseUrl, resource, remediation_file, putCall, pluginName, function(err, action) {
            if (err) return callback(err);
            if (action) action.action = putCall;


            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'Enabled'
            };

            callback(null, action);
        });
    }
};
