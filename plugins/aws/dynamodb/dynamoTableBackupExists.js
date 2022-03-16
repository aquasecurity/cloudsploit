var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DynamoDB Table Backup Exists',
    category: 'DynamoDB',
    domain: 'Databases',
    description: 'Ensures that Amazon DynamoDB tables are using on-demand backups.',
    more_info: 'With AWS Backup, you can configure backup policies and monitor activity for your AWS resources and on-premises workloads in one place. Using DynamoDB with AWS Backup, you can copy your on-demand backups across AWS accounts and regions, add cost allocation tags to on-demand backups, and transition on-demand backups to cold storage for lower costs.',
    link: 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/BackupRestore.html',
    recommended_action: 'Create on-demand backups for DynamoDB tables.',
    apis: ['DynamoDB:listTables', 'DynamoDB:listBackups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

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

            var listBackups = helpers.addSource(cache, source,
                ['dynamodb', 'listBackups', region]);

            if (!listBackups || listBackups.err || !listBackups.data || !listBackups.data.BackupSummaries) {
                helpers.addResult(results, 3,
                    `Unable to query for DynamoDB backups: ${helpers.addError(listBackups)}`,
                    region);
                return rcb();
            }

            for (let table of listTables.data){
                let backupTable = listBackups.data.BackupSummaries.find(backup => backup.TableName == table);
                if (!backupTable) {
                    helpers.addResult(results, 2, 'No backup exists for DynamoDB table', 
                        region);    
                } else {
                    helpers.addResult(results, 0, 'Backup exists for DynamoDB table', 
                        region);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
