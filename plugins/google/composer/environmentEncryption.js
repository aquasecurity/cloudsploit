var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Environment Encryption',
    category: 'Cloud Composer',
    domain: 'Content Delivery',
    severity: 'High',
    description: 'Ensure Composer environments have encryption enabled using desired protection level.',
    more_info: 'Within a Composer environment, data is encrypted by default using Google-managed encryption keys. To adhere to security compliance standards and have more control over the keys and encryption process, ensure the environment is encrypted with desired encryption level.',
    link: 'https://cloud.google.com/composer/docs/cmek',
    recommended_action: 'Ensure that all composer environments have desired encryption level.',
    apis: ['composer:environments', 'keyRings:list', 'cryptoKeys:list'],
    settings: {
        environment_encryption_level: {
            name: 'Environment Encryption Level',
            description: 'Desired protection level for composer environments. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM encryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        }
    },
    realtime_triggers: ['orchestration.airflow.service.Environments.CreateEnviroments', 'orchestration.airflow.service.Environments.DeleteEnvironment'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let desiredEncryptionLevelStr = settings.environment_encryption_level || this.settings.environment_encryption_level.default;
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
                async.each(regions.composer, function(region, rcb) {

                    let environments = helpers.addSource(
                        cache, source, ['composer', 'environments', region]);

                    if (!environments) return rcb();

                    if (environments.err || !environments.data) {
                        helpers.addResult(results, 3, 'Unable to query Composer environments: ' + helpers.addError(environments), region, null, null, environments.err);
                        return rcb();
                    }

                    if (!environments.data.length) {
                        helpers.addResult(results, 0, 'No Composer environments found', region);
                        return rcb();
                    }
                    
                    if (environments && environments.data) {
                        environments.data.forEach(environment => {
                            let currentEncryptionLevel;
                           
                            if (environment && environment.config && environment.config.encryptionConfig && environment.config.encryptionConfig.kmsKeyName
                                && keysObj[environment.config.encryptionConfig.kmsKeyName]) {
                                currentEncryptionLevel = helpers.getProtectionLevel(keysObj[environment.config.encryptionConfig.kmsKeyName], helpers.PROTECTION_LEVELS);
                            } else {
                                currentEncryptionLevel = 1; //default
                            }

                            let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];

                            if (currentEncryptionLevel >= desiredEncryptionLevel) {
                                helpers.addResult(results, 0,
                                    `Composer environment has encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`,
                                    region, environment.name);
                            } else {
                                helpers.addResult(results, 2,
                                    `Composer environment has encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`,
                                    region, environment.name);
                            }
                        });
                    }
                    
                    rcb();
                }, function() {
                    cb();
                });
            }
        ], function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};