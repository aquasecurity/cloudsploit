var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudTrail Encryption',
    category: 'CloudTrail',
    description: 'Ensures CloudTrail encryption at rest is enabled for logs',
    more_info: 'CloudTrail log files contain sensitive information about an account and should be encrypted at rest for additional protection.',
    recommended_action: 'Enable CloudTrail log encryption through the CloudTrail console or API',
    link: 'http://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html',
    apis: ['CloudTrail:describeTrails'],
    compliance: {
        cis2: '2.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs'
    },
    remediation_description: 'Encryption for the affected Cloud trails will be enabled.',
    remediation_min_version: '202010302230',
    apis_remediate: ['CloudTrail:describeTrails'],
    remediation_inputs: {
        kmsKeyIdforCt: {
            name: '(Mandatory) KMS Key ID',
            description: 'The KMS Key ID used for encryption',
            regex: '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$',
            required: true
        }
    },
    actions: {
        remediate: ['CloudTrail:updateTrail'],
        rollback: ['CloudTrail:updateTrail']
    },
    permissions: {
        remediate: ['cloudtrail:UpdateTrail'],
        rollback: ['cloudtrail:UpdateTrail']
    },
    realtime_triggers: ['cloudtrail:CreateTrail', 'cloudtrail:UpdateTrail'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.cloudtrail, function(region, rcb){
            var describeTrails = helpers.addSource(cache, source,
                ['cloudtrail', 'describeTrails', region]);

            if (!describeTrails) return rcb();

            if (describeTrails.err || !describeTrails.data) {
                helpers.addResult(results, 3,
                    'Unable to query for CloudTrail encryption status: ' + helpers.addError(describeTrails), region);
                return rcb();
            }

            if (!describeTrails.data.length) {
                helpers.addResult(results, 2, 'CloudTrail is not enabled', region);
            } else if (describeTrails.data[0]) {
                for (var t in describeTrails.data) {
                    if (describeTrails.data[t].S3BucketName == helpers.CLOUDSPLOIT_EVENTS_BUCKET) continue;
                    if (!describeTrails.data[t].KmsKeyId) {
                        helpers.addResult(results, 2, 'CloudTrail encryption is not enabled',
                            region, describeTrails.data[t].TrailARN);
                    } else {
                        helpers.addResult(results, 0, 'CloudTrail encryption is enabled',
                            region, describeTrails.data[t].TrailARN);
                    }
                }
            } else {
                helpers.addResult(results, 2, 'CloudTrail is enabled but is not properly configured', region);
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'cloudtrailEncryption';
        var ctNameArr = resource.split(':');
        var ctName = ctNameArr[ctNameArr.length - 1].split('/');
        // find the location of the ct needing to be remediated

        var ctLocation = ctNameArr[3];
        var err;
        // add the location of the ct to the config
        config.region = ctLocation;
        var params = {};

        // create the params necessary for the remediation
        if (settings.input &&
            settings.input.kmsKeyIdforCt) {
            params = {
                'Name': resource,
                'KmsKeyId': settings.input.kmsKeyIdforCt,
            };
        } else {
            err = 'KmsKeyId is mandatory to enable encryption';
            return callback(err, null);
        }

        var remediation_file = settings.remediation_file;
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'Encryption': 'Disabled',
            'CloudTrail': resource
        };
        // passes the config, put call, and params to the remediate helper function
        helpers.remediatePlugin(config, putCall[0], params, function(err) {
            if (err) {
                remediation_file['remediate']['actions'][pluginName]['error'] = err;
                return callback(err, null);
            }

            let action = params;
            action.action = putCall;

            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'ENCRYPTED',
                'CloudTrail': ctName
            };

            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};