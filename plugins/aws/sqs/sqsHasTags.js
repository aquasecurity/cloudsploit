var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SQS Has Tags',
    category: 'SQS',
    domain: 'Application Integration',
    severity: 'Low',
    description: 'Ensures that Amazon SQS queue has tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Update SQS queue and add tags.',
    link: 'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-queue-tags.html',
    apis: ['SQS:listQueues', 'STS:getCallerIdentity', 'ResourceGroupsTaggingAPI:getResources'],
    realtime_triggers: ['sqs:CreateQueue', 'sqs:SetQueueAttributes', 'sqs:DeleteQueue'],

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

            if (listQueues.err || !listQueues.data) {
                helpers.addResult(results, 3,
                    `Unable to query for SQS queues: ${helpers.addError(listQueues)}`, region);
                return rcb();
            }

            if (!listQueues.data.length) {
                helpers.addResult(results, 0, 'No SQS queues found', region);
                return rcb();
            }

            const arnList = [];
            for (let queueUrl of listQueues.data){
                var queueName = queueUrl.split('/');
                queueName = queueName[queueName.length-1];

                var resource = `arn:${awsOrGov}:sqs:${region}:${accountId}:${queueName}`;
                arnList.push(resource);
            }

            helpers.checkTags(cache, 'SQS queue', arnList, region, results, settings);
            return rcb();

        }, function(){
            callback(null, results, source);
        });
    }
}; 
            