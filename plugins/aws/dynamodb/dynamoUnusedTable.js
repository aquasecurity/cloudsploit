var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DynamoDB Empty Table',
    category: 'DynamoDB',
    domain: 'Databases',
    description: 'Ensures that Amazon DynamoDB empty tables are removed to optimise costs.',
    severity: 'Low',
    more_info: 'A DynamoDB table is considered unused if its item count is zero. As a best practice, delete unused tables for operational efficiency and better resource management. This will also prevent resource wastage and unnecessary costs. This plugin might produce false positives or false negatives as AWS updates table count every 6 hours.',
    link: 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithTables.Basics.html',
    recommended_action: 'Remove unused tables if you no longer need them.',
    apis: ['DynamoDB:listTables', 'DynamoDB:describeTable', 'STS:getCallerIdentity'],
    realtime_triggers: ['dynamodb:CreateTable','dynamodb:DeleteTable'],

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
                    `Unable to query for DynamoDB tables: ${helpers.addError(listTables)}`, region);
                return rcb();
            }

            if (!listTables.data.length) {
                helpers.addResult(results, 0, 'No DynamoDB tables found', region);
                return rcb();
            }

            for (let table of listTables.data){
                var resource = `arn:${awsOrGov}:dynamodb:${region}:${accountId}:table/${table}`;

                var describeTable = helpers.addSource(cache, source,
                    ['dynamodb', 'describeTable', region, table]);

                if (!describeTable || describeTable.err || !describeTable.data) {
                    helpers.addResult(results, 3,
                        `Unable to describe DynamoDB table: ${helpers.addError(describeTable)}`,
                        region, resource);
                    continue;
                }

                if (describeTable.data && describeTable.data.Table && !describeTable.data.Table.ItemCount) {
                    helpers.addResult(results, 2,
                        `DynamoDB table "${table}" is empty`,
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        `DynamoDB table "${table}" is being used`,
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
