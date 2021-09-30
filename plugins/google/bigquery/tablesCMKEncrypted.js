var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Tables CMK Encrypted',
    category: 'BigQuery',
    description: 'Ensure that BigQuery dataset tables are encrypted using desired encryption protection level.',
    more_info: 'By default Google encrypts all datasets using Google-managed encryption keys. To have more control over the encryption process of your BigQuery dataset tables you can use Customer-Managed Keys (CMKs).',
    link: 'https://cloud.google.com/bigquery/docs/customer-managed-encryption',
    recommended_action: 'Ensure that each BigQuery dataset table has desired encryption level.',
    apis: ['datasets:list', 'datasets:get', 'projects:get', 'keyRings:list', 'cryptoKeys:list'],
    settings: {
        bigquery_tables_encryption_protection_level: {
            name: 'BigQuery Dataset Encryption Protection Level',
            description: 'Desired protection level for BigQuery datasets. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM encryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        }
    },

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

        var project = projects.data[0].name;
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
                async.each(regions.datasets, function(region, rcb) {
                    let datasetsGet = helpers.addSource(cache, source,
                        ['datasets', 'get', region]);

                    if (!datasetsGet) return rcb();

                    if (datasetsGet.err || !datasetsGet.data) {
                        helpers.addResult(results, 3, 'Unable to query BigQuery datasets: ' + helpers.addError(datasetsGet), region);
                        return rcb();
                    }

                    if (!datasetsGet.data.length) {
                        helpers.addResult(results, 0, 'No BigQuery datasets found', region);
                        return rcb();
                    }

                    async.each(datasetsGet.data, (dataset, dcb) => {
                        if (!dataset.id) return dcb();

                        let resource = helpers.createResourceName('datasets', dataset.id.split(':')[1] || dataset.id, project);

                        let currentEncryptionLevel;

                        if (dataset.defaultEncryptionConfiguration && dataset.defaultEncryptionConfiguration.kmsKeyName) {
                            currentEncryptionLevel = helpers.getProtectionLevel(keysObj[dataset.defaultEncryptionConfiguration.kmsKeyName], helpers.PROTECTION_LEVELS);
                        } else {
                            currentEncryptionLevel = 1; //default
                        }

                        let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];

                        if (currentEncryptionLevel >= desiredEncryptionLevel) {
                            helpers.addResult(results, 0,
                                `BigQuery dataset has encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`,
                                region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                `BigQuery dataset has encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`,
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
