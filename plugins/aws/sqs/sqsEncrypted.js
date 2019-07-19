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
    }
};