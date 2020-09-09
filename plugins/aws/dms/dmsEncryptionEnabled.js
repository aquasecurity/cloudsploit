var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DMS Encryption Enabled',
    category: 'DMS',
    description: 'Ensures DMS encryption is enabled using a CMK',
    more_info: 'Data sent through the data migration service is encrypted using KMS. Encryption is enabled by default, but it is recommended to use customer managed keys.',
    recommended_action: 'Enable encryption using KMS CMKs for all DMS replication instances.',
    link: 'https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html',
    apis: ['DMS:describeReplicationInstances', 'KMS:listKeys', 'KMS:describeKey', 'KMS:listAliases'],
    compliance: {
        hipaa: 'DMS encryption must be used when processing any HIPAA-related data. ' +
            'AWS KMS encryption ensures that the DMS replication instance meets the ' +
            'encryption in transit and at rest requirements of HIPAA.'
    },
    settings: {
        dms_encryption_allow_pattern: {
            name: 'DMS Encryption Allow Pattern',
            description: 'When set, whitelists DMS instances matching the given pattern. Useful for overriding buckets outside the account control.',
            regex: '^.{1,255}$',
            default: false
        },
        dms_encryption_kms_alias: {
            name: 'DMS Encryption KMS Alias',
            description: 'If set, DMS encryption must be configured using the KMS key alias specified. Be sure to include the alias/ prefix. Comma-delimited.',
            regex: '^alias/[a-zA-Z0-9_/-,]{0,256}$',
            default: false
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            dms_encryption_allow_pattern: settings.dms_encryption_allow_pattern || this.settings.dms_encryption_allow_pattern.default,
            dms_encryption_kms_alias: settings.dms_encryption_kms_alias || this.settings.dms_encryption_kms_alias.default,
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var aliasKeyIds = [];
        var defaultKeyIds = [];
        var defaultKeyDesc = 'Default master key that protects my DMS replication';

        async.series([
            // Lookup the default master key for DMS if required
            function(cb) {
                async.each(regions.kms, function(region, rcb) {
                    // List the KMS Keys
                    var listKeys = helpers.addSource(cache, source, ['kms', 'listKeys', region]);

                    if (!listKeys) return rcb();

                    if (listKeys.err || !listKeys.data) {
                        return rcb();
                    }
                    if (!listKeys.data.length) return rcb();

                    async.each(listKeys.data, function(key, kcb){
                        // Describe the KMS keys
                        var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, key.KeyId]);

                        if (describeKey && describeKey.data && describeKey.data.KeyMetadata) {
                            var keyToAdd = describeKey.data.KeyMetadata;

                            if (keyToAdd.KeyManager && keyToAdd.KeyManager == 'AWS' && keyToAdd.Description &&
                                keyToAdd.Description.indexOf(defaultKeyDesc) === 0) {
                                defaultKeyIds.push(keyToAdd.Arn);
                            }
                        }

                        kcb();
                    }, function(){
                        rcb();
                    });
                }, function(){
                    cb();
                });
            },
            // Lookup the key aliases if required
            function(cb) {
                if (!config.dms_encryption_kms_alias) return cb();
                var configAliasIds = config.dms_encryption_kms_alias.split(',');

                async.each(regions.kms, function(region, rcb) {
                    var listAliases = helpers.addSource(cache, source,
                        ['kms', 'listAliases', region]);

                    var aliasIds = [];

                    if (!listAliases || listAliases.err ||
                        !listAliases.data) {
                        return rcb();
                    }

                    if (!listAliases.data.length) {
                        return rcb();
                    }

                    listAliases.data.forEach(function(alias){
                        if (configAliasIds.indexOf(alias.AliasName) > -1) {
                            aliasIds.push(alias.AliasArn.replace(/:alias\/.*/, ':key/' + alias.TargetKeyId));
                        }
                    });

                    if (aliasIds.length) aliasKeyIds = aliasKeyIds.concat(aliasIds);

                    rcb();
                }, function(){
                    cb();
                });
            },
            // Check the DMS Instances for encryption
            function(cb) {
                async.each(regions.dms, function(region, rcb) {
                    // List the KMS Keys
                    var describeReplicationInstances = helpers.addSource(cache, source,
                        ['dms', 'describeReplicationInstances', region]);

                    if (!describeReplicationInstances) return rcb();

                    if (describeReplicationInstances.err || !describeReplicationInstances.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for replication instances: ' + helpers.addError(describeReplicationInstances), region);
                        return rcb();
                    }

                    if (!describeReplicationInstances.data.length) {
                        helpers.addResult(results, 0, 'No replication instances found', region);
                        return rcb();
                    }

                    var allowRegex = (config.dms_encryption_allow_pattern &&
                        config.dms_encryption_allow_pattern.length) ? new RegExp(config.dms_encryption_allow_pattern) : false;

                    describeReplicationInstances.data.forEach(function(instance){
                        if (allowRegex && allowRegex.test(instance.ReplicationInstanceIdentifier)) {
                            helpers.addResult(results, 0,
                                'The replication instance: ' + instance.ReplicationInstanceIdentifier+ ' is whitelisted via custom setting.',
                                region, instance.ReplicationInstanceArn, custom);
                        } else {
                            if (instance.KmsKeyId) {
                                var keyArn = instance.KmsKeyId;

                                if (config.dms_encryption_kms_alias) {
                                    if (!aliasKeyIds.length) {
                                        helpers.addResult(results, 2,
                                            'The replication instance: ' + instance.ReplicationInstanceIdentifier + ' has encryption enabled but matching KMS key alias ' + config.dms_encryption_kms_alias + ' could not be found in the account',
                                            region, instance.ReplicationInstanceArn, custom);
                                    } else if (aliasKeyIds.indexOf(keyArn) > -1) {
                                        helpers.addResult(results, 0,
                                            'The replication instance: ' + instance.ReplicationInstanceIdentifier + ' has encryption enabled using required KMS key: ' + keyArn,
                                            region, instance.ReplicationInstanceArn, custom);
                                    }
                                } else if (defaultKeyIds.length && defaultKeyIds.indexOf(keyArn) > -1) {
                                    helpers.addResult(results, 2,
                                        'Replication instance: ' + instance.ReplicationInstanceIdentifier + ' has default kms/dms encryption enabled',
                                        region, instance.ReplicationInstanceArn);
                                } else {
                                    helpers.addResult(results, 0,
                                        'The replication instance: ' + instance.ReplicationInstanceIdentifier + ' has CMK encryption enabled',
                                        region, instance.ReplicationInstanceArn, custom);
                                }

                            } else {
                                helpers.addResult(results, 2,
                                    'Replication instance: ' + instance.ReplicationInstanceIdentifier + ' has default kms/dms encryption',
                                    region, instance.ReplicationInstanceArn);
                            }
                        }
                    });
                    rcb();
                }, function(){
                    cb();
                });
            }
        ], function(){
            callback(null, results, source);
        });
    }
};
