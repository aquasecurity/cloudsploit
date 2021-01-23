var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SQS Dead Letter Queue',
    category: 'SQS',
    description: 'Ensures that each Amazon SQS queue has Dead Letter Queue configured.',
    more_info: 'Amazon SQS queues should have dead letter queue configured to avoid data loss for unprocessed messages.',
    recommended_action: 'Update Amazon SQS queue and configure dead letter queue.',
    link: 'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html',
    apis: ['SQS:listQueues', 'SQS:getQueueAttributes', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.sqs, function(region, rcb){
            var listQueues = helpers.addSource(cache, source,
                ['sqs', 'listQueues', region]);

            if (!listQueues) return rcb();

            if (listQueues.err) {
                helpers.addResult(results, 3,
                    `Unable to query for Amazon SQS queues: ${helpers.addError(listQueues)}`, region);
                return rcb();
            }

            if (!listQueues.data || !listQueues.data.length) {
                helpers.addResult(results, 0, 'No Amazon SQS queues found', region);
                return rcb();
            }

            async.each(listQueues.data, function(queueUrl, cb){
                var queueName = queueUrl.split('/');
                queueName = queueName[queueName.length-1];

                var resource = `arn:${awsOrGov}:sqs:${region}:${accountId}:${queueName}`;
                var getQueueAttributes = helpers.addSource(cache, source,
                    ['sqs', 'getQueueAttributes', region, queueUrl]);

                if (!getQueueAttributes || getQueueAttributes.err || !getQueueAttributes.data ||
                    !getQueueAttributes.data.Attributes || !getQueueAttributes.data.Attributes.QueueArn) {
                    helpers.addResult(results, 3,
                        `Unable to query queue attributes for Amazon SQS queue: ${helpers.addError(getQueueAttributes)}`,
                        region, resource);
                    return cb();
                }

                if (getQueueAttributes.data.Attributes.RedrivePolicy &&
                    getQueueAttributes.data.Attributes.RedrivePolicy.length) {
                    helpers.addResult(results, 0,
                        'Amazon SQS queue has dead letter queue configured',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Amazon SQS queue does not have dead letter queue configured',
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