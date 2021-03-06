var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SQS Public Access',
    category: 'SQS',
    description: 'Ensures that SQS queues are not publicly accessible',
    more_info: 'SQS queues should be not be publicly accessible to prevent unauthorized actions.',
    recommended_action: 'Update the SQS queue policy to prevent public access.',
    link: 'http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies.html',
    apis: ['SQS:listQueues', 'SQS:getQueueAttributes', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source,
            ['sts', 'getCallerIdentity', acctRegion, 'data']);
        var awsOrGov = helpers.defaultPartition(settings);

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

            async.each(listQueues.data, function(queue, cb){
                var queueName = queue.substr(queue.lastIndexOf('/') + 1);
                var resource = `arn:${awsOrGov}:sqs:${region}:${accountId}:${queueName}`;

                var getQueueAttributes = helpers.addSource(cache, source,
                    ['sqs', 'getQueueAttributes', region, queue]);

                if (!getQueueAttributes ||
                    getQueueAttributes.err ||
                    !getQueueAttributes.data ||
                    !getQueueAttributes.data.Attributes) {
                    helpers.addResult(results, 3,
                        `Unable to query attributes for queue "${queueName}"`,
                        region, resource);

                    return cb();
                }

                if (!getQueueAttributes.data.Attributes.Policy) {
                    helpers.addResult(results, 0,
                        `SQS queue "${queueName}" does not use a policy`,
                        region, resource);
                    return cb();
                }

                var statements = helpers.normalizePolicyDocument(getQueueAttributes.data.Attributes.Policy);

                var publicStatements = [];
                for (var s in statements) {
                    var statement = statements[s];

                    if (statement.Effect &&
                        statement.Effect === 'Allow' &&
                        helpers.globalPrincipal(statement.Principal)) {
                        publicStatements.push(statement);
                    }
                }

                if (!publicStatements.length) {
                    helpers.addResult(results, 0,
                        `SQS queue "${queueName}" is not publicly accessible`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `SQS queue "${queueName}" is publicly accessible`,
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