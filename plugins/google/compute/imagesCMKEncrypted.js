var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Images CMK Encrypted',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensure Compute Images are encrypted using Customer Managed or Supplied Keys',
    more_info: 'Compute Images are encrypted by default using the Google-managed encryption keys. However, for highly sensitive images and more control over the encryption and decryption process, use either customer-managed keys or customer-supplied keys for encryption.',
    link: 'https://cloud.google.com/compute/docs/disks/customer-supplied-encryption',
    recommended_action: 'Ensure that all Compute Images are encrypted using desired protection level.',
    apis: ['images:list', 'keyRings:list', 'cryptoKeys:list'],
    settings: {
        image_encryption_level: {
            name: 'Image Encryption Protection Level',
            description: 'Desired protection level for Compute Image. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM ecnryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let desiredEncryptionLevelStr = settings.image_encryption_level || this.settings.image_encryption_level.default;
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

                    if (cryptoKeys && cryptoKeys.data && cryptoKeys.data.length) {
                        helpers.listToObj(keysObj, cryptoKeys.data, 'name');
                    }
                    rcb();
                }, function() {
                    cb();
                });
            },
            function(cb) {

                let images = helpers.addSource(cache, source,
                    ['images', 'list', 'global']);
        
                if (!images || images.err || !images.data) {
                    helpers.addResult(results, 3, 'Unable to query Compute Images: ' + helpers.addError(images), 'global');
                    return callback(null, results, source);
                }
        
                if (!images.data.length) {
                    helpers.addResult(results, 0, 'No Compute Images found', 'global');
                    return callback(null, results, source);
                }
                
                images.data.forEach(image => {

                    let resource = helpers.createResourceName('images', image.name, project, 'global');
                    let currentEncryptionLevel = 1; // default

                    if (image.imageEncryptionKey && image.imageEncryptionKey.kmsKeyName) {
                        let keyName = Object.keys(keysObj).find(key => image.imageEncryptionKey.kmsKeyName.includes(key));
                        if (keyName) {
                            currentEncryptionLevel = helpers.getProtectionLevel(keysObj[keyName], helpers.PROTECTION_LEVELS);
                        }
                    }

                    let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];

                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
                        helpers.addResult(results, 0,
                            `Compute Image has encryption level ${currentEncryptionLevelStr} which is greater than or equal to ${desiredEncryptionLevelStr}`, 'global', resource);
                    } else {
                        helpers.addResult(results, 2,
                            `Compute Image has encryption level ${currentEncryptionLevelStr} which is less than ${desiredEncryptionLevelStr}`, 'global', resource);
                    }
                });

                cb();
            }
        ], function() {
            callback(null, results, source);
        });
    }
};