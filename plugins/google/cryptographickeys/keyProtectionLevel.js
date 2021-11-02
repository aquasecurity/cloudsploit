var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Key Protection Level',
    category: 'Cryptographic Keys',
    domain: 'Identity and Access Management',
    description: 'Ensure that cryptographic keys have protection level equal to or above desired protection level.',
    more_info: 'Cloud KMS cryptographic keys should be created with protection level set by your organization\'s compliance and security rules.',
    link: 'https://cloud.google.com/kms/docs/reference/rest/v1/ProtectionLevel',
    recommended_action: 'Create cryptographic keys according to desired protection level',
    apis: ['keyRings:list','cryptoKeys:list'],
    settings: {
        kms_crypto_keys_protection_level: {
            name: 'Cloud Cryptographic Keys Desired Protection Level',
            description: 'Desired protection level for cryptographic keys. cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM ecnryption key, external: imported or externally managed key',
            regex: '^(cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        var config = {
            desiredProtectionLevel: settings.kms_crypto_keys_protection_level || this.settings.kms_crypto_keys_protection_level.default
        };

        async.each(regions.keyRings, function(region, rcb){
            let keyRings = helpers.addSource(
                cache, source, ['keyRings', 'list', region]);

            if (!keyRings) return rcb();

            if (keyRings.err || !keyRings.data) {
                helpers.addResult(results, 3, 'Unable to query key rings', region, null, null, keyRings.err);
                return rcb();
            }

            if (!keyRings.data.length) {
                helpers.addResult(results, 0, 'No key rings found', region);
                return rcb();
            }

            let cryptoKeys = helpers.addSource(
                cache, source, ['cryptoKeys', 'list', region]);

            if (!cryptoKeys) return rcb();

            if (cryptoKeys.err || !cryptoKeys.data) {
                helpers.addResult(results, 3, 'Unable to query cryptographic keys', region, null, null, cryptoKeys.err);
                return rcb();
            }

            if (!cryptoKeys.data.length) {
                helpers.addResult(results, 0, 'No cryptographic keys found', region);
                return rcb();
            }

            cryptoKeys.data.forEach(cryptoKey => {
                let currentProtectionLevel = helpers.getProtectionLevel(cryptoKey, helpers.PROTECTION_LEVELS);
                let currentProtectionLevelStr = helpers.PROTECTION_LEVELS[currentProtectionLevel];
                if (currentProtectionLevel >= helpers.PROTECTION_LEVELS.indexOf(config.desiredProtectionLevel)) {
                    helpers.addResult(results, 0,
                        `Key protection level is ${currentProtectionLevelStr} which is greater than or equal to ${config.desiredProtectionLevel}`,
                        region, cryptoKey.name);
                } else {
                    helpers.addResult(results, 2,
                        `Key protection level is ${currentProtectionLevelStr} which is less than ${config.desiredProtectionLevel}`,
                        region, cryptoKey.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};