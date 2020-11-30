var async = require('async');
var helpers = require('../../../helpers/aws');

var defaultKmsKey = 'alias/aws/sqs';

module.exports = {
    title: 'SQS Encrypted',
    category: 'SQS',
    description: 'Ensures SQS encryption is enabled',
    more_info: 'Messages sent to SQS queues can be encrypted using KMS server-side encryption. Existing queues can be modified to add encryption with minimal overhead.',
    recommended_action: 'Enable encryption using KMS for all SQS queues.',
    link: 'http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html',
    apis: ['SQS:listQueues', 'SQS:getQueueAttributes'],
    compliance: {
        hipaa: 'SQS encryption must be used when processing any HIPAA-related data. ' +
                'AWS KMS encryption ensures that the SQS message payload meets the ' +
                'encryption in transit and at rest requirements of HIPAA.',
        pci: 'PCI requires proper encryption of cardholder data at rest. SQS ' +
             'encryption should be enabled for all queues processing this type ' +
             'of data.'
    },
    remediation_description: 'Encryption for the affected SQS queues will be enabled.',
    remediation_min_version: '202010302230',
    apis_remediate: ['SQS:listQueues', 'SQS:getQueueAttributes'],
    remediation_inputs: {
        kmsKeyIdforSqs: {
            name: '(Optional) KMS Key ID',
            description: 'The KMS Key ID used for encryption',
            regex: '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$',
            required: false
        }
    },
    actions: {
        remediate: ['SQS:setQueueAttributes'],
        rollback: ['SQS:setQueueAttributes']
    },
    permissions: {
        remediate: ['sqs:SetQueueAttributes'],
        rollback: ['sqs:SetQueueAttributes']
    },
    realtime_triggers: ['sqs:CreateQueue', 'sqs:SetQueueAttributes'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.sqs_encrypted, function(region, rcb){
            var listQueues = helpers.addSource(cache, source,
                ['sqs', 'listQueues', region]);

            if (!listQueues) return rcb();

            if (listQueues.err) {
                helpers.addResult(results, 3,
                    'Unable to query for SQS queues: ' + helpers.addError(listQueues), region);
                return rcb();
            }

            if (!listQueues.data || !listQueues.data.length) {
                helpers.addResult(results, 0, 'No SQS queues found', region);
                return rcb();
            }

            async.each(listQueues.data, function(queue, cb){
                
                var getQueueAttributes = helpers.addSource(cache, source,
                    ['sqs', 'getQueueAttributes', region, queue]);

                if (!getQueueAttributes ||
                    (!getQueueAttributes.err && !getQueueAttributes.data)) return cb();

                if (getQueueAttributes.err ||
                    !getQueueAttributes.data ||
                    !getQueueAttributes.data.Attributes ||
                    !getQueueAttributes.data.Attributes.QueueArn) {
                    helpers.addResult(results, 3,
                        'Unable to query SQS for queue: ' + queue,
                        region);

                    return cb();
                }

                var queueArn = getQueueAttributes.data.Attributes.QueueArn;

                if (getQueueAttributes.data.Attributes.KmsMasterKeyId) {
                    if (getQueueAttributes.data.Attributes.KmsMasterKeyId === defaultKmsKey) {
                        helpers.addResult(results, 1,
                            'The SQS queue uses the default KMS key (' + defaultKmsKey + ') for SSE',
                            region, queueArn);
                    } else {
                        helpers.addResult(results, 0,
                            'The SQS queue uses a KMS key for SSE',
                            region, queueArn);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'The SQS queue does not use a KMS key for SSE',
                        region, queueArn);
                }

                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    },

    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'sqsEncrypted';
        var queueNameArr = resource.split(':');
        var queueName = queueNameArr[queueNameArr.length - 1];

        // find the location of the Queue needing to be remediated
        var queAttributes = cache['sqs']['getQueueAttributes'];
        var queueLocation = queueNameArr[3];
        var queueUrl;
        var err;
        if (!queAttributes || queAttributes.err || !Object.keys(queAttributes).length){
            err =  queAttributes.err || 'Unable to get queue location';
            return callback(err, null);
        }

        for(var qUrl in queAttributes[queueLocation]){
            if (queAttributes[queueLocation][qUrl].data.Attributes.QueueArn === resource){
                queueUrl = qUrl;
                break;
            }
        }

        if (!queueUrl) {
            err = 'Unable to get queue url';
            return callback(err, null);
        }
        // add the location of the Queue to the config
        config.region = queueLocation;
        var params = {};
        // create the params necessary for the remediation
        if (settings.input &&
            settings.input.kmsKeyIdforSqs) {
            params = {
                Attributes: {
                    'KmsMasterKeyId': settings.input.kmsKeyIdforSqs,
                },
                QueueUrl: queueUrl
            };
        } else {
            params = {
                Attributes: {
                    'KmsMasterKeyId': defaultKmsKey,
                },
                QueueUrl: queueUrl
            };
        }

        var remediation_file = settings.remediation_file;

        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'Encryption': 'Disabled',
            'Queue': queueName
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
                'Queue': queueName
            };
            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    },

    rollback: function(config, cache, settings, resource, callback) {
        console.log('Rollback support for this plugin has not yet been implemented');
        console.log(config, cache, settings, resource);
        callback();
    }
};