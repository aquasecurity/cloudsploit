var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DynamoDB Table Has Tags',
    category: 'DynamoDB',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensure that DynamoDB tables have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Tagging.html',
    recommended_action: 'Modify DynamoDB table and add tags.',
    apis: ['DynamoDB:listTables', 'ResourceGroupsTaggingAPI:getResources', 'STS:getCallerIdentity'],
    realtime_triggers: ['dynamodb:CreateTable','dynamodb:TagResource','dynamodb:UntagResource','dynamodb:DeleteTable'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.dynamodb, function(region, rcb){
            var listTables = helpers.addSource(cache, source,
                ['dynamodb', 'listTables', region]); 

            if (!listTables) return rcb();

            if (listTables.err || !listTables.data) {
                helpers.addResult(results, 3,
                    `Unable to query for DynamoDB tables: ${helpers.addError(listTables)}`,
                    region);
                return rcb();
            }

            if (!listTables.data.length) {
                helpers.addResult(results, 0, 'No DynamoDB tables found', region);
                return rcb();
            }

            const ARNList = [];
            for (let table of listTables.data){
                var resource = `arn:${awsOrGov}:dynamodb:${region}:${accountId}:table/${table}`;
                ARNList.push(resource);
            }
            helpers.checkTags(cache, 'DynamoDB table', ARNList, region, results, settings);
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
