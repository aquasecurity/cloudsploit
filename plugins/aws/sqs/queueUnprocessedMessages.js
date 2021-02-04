var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SQS Queue Unprocessed Messages',
    category: 'SQS',
    description: 'Ensures that Amazon SQS queue has not reached unprocessed messages limit.',
    more_info: 'Amazon SQS queues should have unprocessed messages less than the limit to be highly available and responsive.',
    recommended_action: 'Set up appropriate message polling time and set up dead letter queue for Amazon SQS queue to handle messages in time',
    link: 'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/working-with-messages.html',
    apis: ['SQS:listQueues', 'SQS:getQueueAttributes', 'STS:getCallerIdentity'],
    settings: {
        unprocessed_messages_limit: {
            name: 'SQS Queue Unprocessed Messages Limit',
            description: 'Maximum allowed limit for SQS queue unprocessed messages',
            regex: '^[0-9]{1,5}',
            default: 1000
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var unprocessedLimit = settings.unprocessed_messages_limit || this.settings.unprocessed_messages_limit.default;
        unprocessedLimit = parseInt(unprocessedLimit);

        async.each(regions.sqs, function(region, rcb){
            var listQueues = helpers.addSource(cache, source,
                ['sqs', 'listQueues', region]);

            if (!listQueues) return rcb();

            if (listQueues.err) {
                helpers.addResult(results, 3,
                    `Unable to query for SQS queues: ${helpers.addError(listQueues)}`, region);
                return rcb();
            }

            if (!listQueues.data || !listQueues.data.length) {
                helpers.addResult(results, 0, 'No SQS queues found', region);
                return rcb();
            }

            async.each(listQueues.data, function(queueUrl, cb){
                var queueName = queueUrl.split('/');
                queueName = queueName[queueName.length-1];

                var resource = `arn:${awsOrGov}:sqs:${region}:${accountId}:${queueName}`;

                var getQueueAttributes = helpers.addSource(cache, source,
                    ['sqs', 'getQueueAttributes', region, queueUrl]);

                if (!getQueueAttributes || getQueueAttributes.err || !getQueueAttributes.data ||
                    !getQueueAttributes.data.Attributes) {
                    helpers.addResult(results, 3,
                        `Unable to query queue attributes: ${helpers.addError(getQueueAttributes)}`,
                        region, resource);
                    return cb();
                }
                
                if (!getQueueAttributes.data.Attributes.ApproximateNumberOfMessages) return cb();

                var unprocessedMessages = getQueueAttributes.data.Attributes.ApproximateNumberOfMessages;
                if (parseInt(unprocessedMessages) <= unprocessedLimit) {
                    helpers.addResult(results, 0,
                        `SQS queue has ${unprocessedMessages} of ${unprocessedLimit} unprocessed messages limit`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `SQS queue has ${unprocessedMessages} of ${unprocessedLimit} unprocessed messages limit`,
                        region, resource);
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