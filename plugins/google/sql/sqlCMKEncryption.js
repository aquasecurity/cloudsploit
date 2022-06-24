var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'SQL CMK Encryption',
    category: 'SQL',
    domain: 'Databases',
    description: 'Ensure that Cloud SQL instances are encrypted using Customer Managed Keys (CMKs).',
    more_info: 'By default, your Google Cloud SQL instances are encrypted using Google-managed keys. To have a better control over the encryption process of your Cloud SQL instances you can use Customer-Managed Keys (CMKs).',
    link: 'https://cloud.google.com/sql/docs/sqlserver/cmek',
    recommended_action: 'Ensure that all Google Cloud SQL instances have desired encryption level.',
    apis: ['instances:sql:list', 'projects:get', 'keyRings:list', 'cryptoKeys:list'],
    settings: {
        sql_encryption_protection_level: {
            name: 'SQL Encryption Protection Level',
            description: 'Desired protection level for Google Cloud SQL instances. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM encryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let desiredEncryptionLevelStr = settings.sql_encryption_protection_level || this.settings.sql_encryption_protection_level.default;
        var desiredEncryptionLevel = helpers.PROTECTION_LEVELS.indexOf(desiredEncryptionLevelStr);

        var keysObj = {};

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, projects.err);
            return callback(null, results, source);
        }

        let project = projects.data[0].name;

        async.series([
            function(cb) {
                async.each(regions.cryptoKeys, function(region, rcb) {
                    let cryptoKeys = helpers.addSource(
                        cache, source, ['cryptoKeys', 'list', region]);
        
                    if (cryptoKeys && cryptoKeys.data && cryptoKeys.data.length) helpers.listToObj(keysObj, cryptoKeys.data, 'name');
                    rcb();
                }, function() {
                    cb();
                });
            },
            function(cb) {
                async.each(regions.instances.sql, function(region, rcb) {
                    let sqlInstances = helpers.addSource(
                        cache, source, ['instances', 'sql', 'list', region]);
                
                    if (!sqlInstances) return rcb();
                
                    if (sqlInstances.err || !sqlInstances.data) {
                        helpers.addResult(results, 3, 'Unable to query SQL instances: ' + helpers.addError(sqlInstances), region);
                        return rcb();
                    }
                
                    if (!sqlInstances.data.length) {
                        helpers.addResult(results, 0, 'No SQL instances found', region);
                        return rcb();
                    }
                
                    sqlInstances.data.forEach(sqlInstance => {
                        if (sqlInstance.instanceType && sqlInstance.instanceType.toUpperCase() === 'READ_REPLICA_INSTANCE') return;
                
                        let resource = helpers.createResourceName('instances', sqlInstance.name, project);
                
                        let currentEncryptionLevel;
        
                        if (sqlInstance.diskEncryptionConfiguration && sqlInstance.diskEncryptionConfiguration.kmsKeyName) {
                            currentEncryptionLevel = helpers.getProtectionLevel(keysObj[sqlInstance.diskEncryptionConfiguration.kmsKeyName], helpers.PROTECTION_LEVELS);
                        } else {
                            currentEncryptionLevel = 1; //default
                        }
        
                        let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];
        
                        if (currentEncryptionLevel >= desiredEncryptionLevel) {
                            helpers.addResult(results, 0,
                                `SQL instance has encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`,
                                region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                `SQL instance has encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`,
                                region, resource);
                        }
                    });
        
                    rcb();
                }, function() {
                    cb();
                });
            }
        ], function() {
            callback(null, results, source);
        });
    }
};


