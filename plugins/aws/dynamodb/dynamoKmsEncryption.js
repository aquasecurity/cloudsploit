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
    remediation_description: 'The impacted DynamoDB table will be configured to use either AES-256 encryption, or CMK-based encryption if a KMS key ID is provided.',
    remediation_min_version: '202010110730',
    apis_remediate: ['DynamoDB:listTables'],
    actions: {
        remediate: ['S3:updateTable'],
        rollback: ['S3:updateTable']
    },
    permissions: {
        remediate: ['s3:UpdateTable'],
        rollback: ['s3:UpdateTable']
    },
    realtime_triggers: ['s3:UpdateTable', 's3:CreateTable'],

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
    },
    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'dynamoKmsEncryption';
        var tableNameArr = resource.split(':');
        var tableName = tableNameArr[tableNameArr.length - 1].split('/')[1];

        var tableLocation = tableNameArr[3];

        // add the location of the table to the config
        config.region = tableLocation;
        var params = {};

        // create the params necessary for the remediation
        if (settings.input &&
            settings.input.kmsKeyId) {
            params = {
                'TableName': tableName,
                'SSESpecification': {
                    'Enabled': true,
                    'KMSMasterKeyId': settings.input.kmsKeyId,
                    'SSEType': 'KMS'
                  }
            };
        } else {
            params = {
                'TableName': tableName,
                'SSESpecification': {
                    'Enabled': true,
                    'SSEType': 'KMS'
                  }
            };
        }

        var remediation_file = settings.remediation_file;

        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'Encryption': 'Default',
            'Bucket': bucketName
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
                'Bucket': bucketName
            };
            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    },
};
