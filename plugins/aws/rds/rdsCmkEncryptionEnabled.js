var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Encrypted With KMS Customer Master Keys',
    category: 'RDS',
    description: 'Ensure RDS instances are encrypted with KMS CMKs in order to have full control over data encryption and decryption.',
    more_info: 'RDS instances should be encrypted with Customer Master Keys',
    link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
    recommended_action: 'RDS does not currently allow modifications to encryption after the instance has been launched, so a new instance will need to be created with KMS CMK encryption enabled.',
    apis: ['RDS:describeDBInstances', 'KMS:listAliases'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var kmsAliases = {};
        var regions = helpers.regions(settings);

        async.each(regions.rds, function(region, rcb){
            var describeDBInstances = helpers.addSource(cache, source,
                ['rds', 'describeDBInstances', region]);

            if (!describeDBInstances) return rcb();

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(results, 3,
                    'Unable to query for RDS instances: ' + helpers.addError(describeDBInstances),
                    region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0, 'No RDS instance found', region);
                return rcb();
            }

            var listAliases = helpers.addSource(cache, source,
                ['kms', 'listAliases', region]);

            if (!listAliases || listAliases.err ||
                !listAliases.data) {
                helpers.addResult(results, 3,
                    'Unable to query for KMS aliases: ' + helpers.addError(listAliases),
                    region, null);
                return rcb();
            }

            if (!listAliases.data.length) {
                helpers.addResult(results, 2, 'No KMS alias found', region, null);
                return rcb();
            }

            var aliasId;
            listAliases.data.forEach(function(alias){
                aliasId = alias.AliasArn.replace(/:alias\/.*/, ':key/' + alias.TargetKeyId);
                kmsAliases[aliasId] = alias.AliasName;
            });

            for (var i in describeDBInstances.data) {
                var db = describeDBInstances.data[i];
                var dbResource = db.DBInstanceArn;
                var kmsKey = db.KmsKeyId;

                if (db.StorageEncrypted) {
                    if (kmsAliases[kmsKey]) {
                        if (kmsAliases[kmsKey] === 'alias/aws/rds'){
                            helpers.addResult(results, 2,
                                'Database instance encryption at rest should be enabled via Customer Master Key rather than default KMS key',
                                region, dbResource);
                        } else {
                            helpers.addResult(results, 0,
                                'Database instance encryption at rest is enabled via Customer Master key',
                                region, dbResource);
                        }
                    }
                    else {
                        helpers.addResult(results, 2,
                            'Database instance encryption key ' + kmsKey + ' not found',
                            region, dbResource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'Database instance does not have encryption at rest enabled',
                        region, dbResource);
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
