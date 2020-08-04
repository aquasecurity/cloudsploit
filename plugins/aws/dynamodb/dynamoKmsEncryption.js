var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DynamoDB KMS Encryption',
    category: 'DynamoDB',
    description: 'Ensures DynamoDB tables are encrypted using a customer-owned KMS key.',
    more_info: 'DynamoDB tables can be encrypted using AWS-owned or customer-owned KMS keys. Customer keys should be used to ensure control over the encryption seed data.',
    link: 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html',
    recommended_action: 'Create a new DynamoDB table using a CMK KMS key.',
    apis: ['DynamoDB:listTables', 'DynamoDB:describeTable', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {

        var results = [];
        var source = {};

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var regions = helpers.regions(settings);

        async.each(regions.dynamodb, function(region, rcb){
            var listTables = helpers.addSource(cache, source,
                ['dynamodb', 'listTables', region]);

            if (!listTables) return rcb();

            if (listTables.err || !listTables.data) {
                helpers.addResult(results, 3,
                    'Unable to query for DynamoDB tables: ' + helpers.addError(listTables), region);
                return rcb();
            }

            if (!listTables.data.length) {
                helpers.addResult(results, 0, 'No DynamoDB tables found', region);
                return rcb();
            }

            for (var i in listTables.data) {
                var table = listTables.data[i];

                var describeTable = helpers.addSource(cache, source,
                    ['dynamodb', 'describeTable', region, table]);

                var arn = 'arn:' + awsOrGov + ':dynamodb:' + region + ':' + accountId + ':table/' + table;

                if (describeTable.err || !describeTable.data || !describeTable.data.Table) {
                    helpers.addResult(results, 3,
                        'Unable to describe DynamoDB table: ' + helpers.addError(describeTable), region, arn);
                    return rcb();
                }

                if (!describeTable.data.Table.SSEDescription) {
                    helpers.addResult(results, 1,
                        'Table is using default encryption with AWS-owned key', region, arn);
                } else {
                    helpers.addResult(results, 0,
                        'Table encryption is enabled with a KMS master key', region, arn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
