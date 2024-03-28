var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DynamoDB Deletion Protection Enabled',
    category: 'DynamoDB',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that DynamoDB tables have deletion protection feature enabled.',
    more_info: 'Enabling deletion protection feature ensures the prevention of accidental deletion of DynamoDB tables during regular maintenance operations, thereby safeguarding your data.',
    link: 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-deletion-protection.html',
    recommended_action: 'Modify DynamoDB table and enable deletion protection.',
    apis: ['DynamoDB:listTables', 'DynamoDB:describeTable', 'sts:getCallerIdentity'],
    realtime_triggers: ['dynamodb:CreateTable','dynamodb:DeleteTable','dynamodb:UpdateTable'],

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

                if (describeTable.data && describeTable.data.Table && describeTable.data.Table.DeletionProtectionEnabled) {
                    helpers.addResult(results, 0,
                        `DynamoDB table "${table}" has deletion protection enabled`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `DynamoDB table "${table}" does not have deletion protection enabled`,
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
