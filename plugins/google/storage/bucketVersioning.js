var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Bucket Versioning',
    category: 'Storage',
    domain: 'Storage',
    severity: 'Low',
    description: 'Ensures object versioning is enabled on storage buckets',
    more_info: 'Object versioning can help protect against the overwriting of objects or data loss in the event of a compromise.',
    link: 'https://cloud.google.com/storage/docs/using-object-versioning',
    recommended_action: 'Bucket Versioning can only be enabled by using the Command Line Interface, use this command to enable Versioning: gsutil versioning set on gs://[BUCKET_NAME]',
    apis: ['buckets:list'],
    remediation_min_version: '202207281836',
    remediation_description: 'Bucket versioning will be enabled on storage buckets',
    apis_remediate: ['buckets:list'],
    actions: {remediate:['storage.buckets.update'], rollback:['storage.buckets.update']},
    permissions: {remediate: ['storage.buckets.setIamPolicy', 'storage.buckets.update'], rollback: ['storage.buckets.setIamPolicy','storage.buckets.update']},
    realtime_triggers: ['storage.buckets.update', 'storage.buckets.create', 'storage.buckets.delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.buckets, function(region, rcb){
            let buckets = helpers.addSource(
                cache, source, ['buckets', 'list', region]);

            if (!buckets) return rcb();

            if (buckets.err || !buckets.data) {
                helpers.addResult(results, 3, 'Unable to query storage buckets: ' + helpers.addError(buckets), region, null, null, buckets.err);
                return rcb();
            }

            if (!helpers.hasBuckets(buckets.data)) {
                helpers.addResult(results, 0, 'No storage buckets found', region);
                return rcb();
            }

            buckets.data.forEach(bucket => {
                if (bucket.name) {
                    let resource = helpers.createResourceName('b', bucket.name);
                    if (bucket.versioning &&
                        bucket.versioning.enabled) {
                        helpers.addResult(results, 0, 'Bucket versioning Enabled', region, resource);
                    } else if ((bucket.versioning &&
                        !bucket.versioning.enabled) ||
                        !bucket.versioning){
                        helpers.addResult(results, 2, 'Bucket versioning not Enabled', region, resource);
                    }
                } else {
                    helpers.addResult(results, 0, 'No storage buckets found', region);
                    return;
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
        var pluginName = 'bucketVersioning';
        var baseUrl = 'https://storage.googleapis.com/storage/v1/{resource}';
        var method = 'PUT';
        var putCall = this.actions.remediate;

        // create the params necessary for the remediation
        var body = {
            versioning: {
                enabled: true
            }
        };
        // logging
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'Versioning': 'Disabled'
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
