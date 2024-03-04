var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Tables CMK Encrypted',
    category: 'BigQuery',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensure that BigQuery dataset tables are encrypted using desired encryption protection level.',
    more_info: 'By default Google encrypts all dataset tables using Google-managed encryption keys. To have more control over the encryption process of your BigQuery dataset tables you can use Customer-Managed Keys (CMKs).',
    link: 'https://cloud.google.com/bigquery/docs/customer-managed-encryption',
    recommended_action: 'Ensure that each BigQuery dataset table has desired encryption level.',
    apis: ['datasets:list', 'bigqueryTables:list', 'bigqueryTables:get', 'keyRings:list', 'cryptoKeys:list'],
    settings: {
        bigquery_tables_encryption_protection_level: {
            name: 'BigQuery Table Encryption Protection Level',
            description: 'Desired protection level for BigQuery tables. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM encryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        }
    },
    realtime_triggers: ['bigquery.TableService.InsertTable','bigquery.TableService.DeleteTable'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let desiredEncryptionLevelStr = settings.bigquery_tables_encryption_protection_level || this.settings.bigquery_tables_encryption_protection_level.default;
        var desiredEncryptionLevel = helpers.PROTECTION_LEVELS.indexOf(desiredEncryptionLevelStr);

        var keysObj = {};

        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

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
                async.each(regions.bigqueryTables, function(region, rcb) {
                    let datasets = helpers.addSource(cache, source,
                        ['datasets', 'list', region]);
        
                    if (!datasets) return rcb();
        
                    if (!datasets.data) {
                        helpers.addResult(results, 3, 'Unable to query BigQuery datasets', region, null, null, datasets.err);
                        return rcb();
                    }
        
                    if (!datasets.data.length) {
                        helpers.addResult(results, 0, 'No BigQuery datasets found', region);
                        return rcb();
                    }
        
                    let tables = helpers.addSource(cache, source,
                        ['bigqueryTables', 'get', region]);
        
                    if (!tables) return rcb();
        
                    if (!tables.data) {
                        helpers.addResult(results, 3, 'Unable to query BigQuery tables', region, null, null, tables.err);
                        return rcb();
                    }
        
                    if (!tables.data.length) {
                        helpers.addResult(results, 0, 'No BigQuery tables found', region);
                        return rcb();
                    }
        
                    tables.data.forEach(table => {
                        if (!table.id) return;

                        let currentEncryptionLevel;
                        let resource = table.selfLink.split('v2/')[1];

                        if (table.encryptionConfiguration && table.encryptionConfiguration.kmsKeyName) {
                            currentEncryptionLevel = helpers.getProtectionLevel(keysObj[table.encryptionConfiguration.kmsKeyName], helpers.PROTECTION_LEVELS);
                        } else {
                            currentEncryptionLevel = 1; //default
                        }

                        let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];

                        if (currentEncryptionLevel >= desiredEncryptionLevel) {
                            helpers.addResult(results, 0,
                                `BigQuery table has encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`,
                                region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                `BigQuery table has encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`,
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