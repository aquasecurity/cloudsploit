var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Key Rotation',
    category: 'Vaults',
    domain: 'Application Integration',
    description: 'Ensure that your OCI Vault Keys are periodically rotated.',
    more_info: 'Rotating keys periodically limits the data encrypted under one key version. Key rotation thereby reduces the risk in case a key is ever compromised.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Tasks/managingkeys.htm',
    recommended_action: 'Ensure that all your cryptographic keys are regenerated (rotated) after a specific period.',
    apis: ['vault:list', 'keys:list', 'keys:get', 'keyVersions:list'],
    settings: {
        key_rotation_interval: {
            name: 'Key Rotation Interval',
            description: 'Return a failing result when keys exceed this number of days without being rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '365'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        var keyRotationInterval = parseInt(settings.key_rotation_interval || this.settings.key_rotation_interval.default);

        async.each(regions.keys, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var keys = helpers.addSource(cache, source,
                    ['keys', 'get', region]);

                if (!keys) return rcb();

                if (keys.err || !keys.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for cryptographic keys: ' + helpers.addError(keys), region);
                    return rcb();
                }

                if (!keys.data.length) {
                    helpers.addResult(results, 0, 'No cryptographic keys found', region);
                    return rcb();
                }

                var keyVersions = helpers.addSource(cache, source,
                    ['keyVersions', 'list', region]);

                if (!keyVersions) return rcb();

                if (keyVersions.err || !keyVersions.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for cryptographic key versions: ' + helpers.addError(keyVersions), region);
                    return rcb();
                }

                if (!keyVersions.data.length) {
                    helpers.addResult(results, 0, 'No key versions found', region);
                    return rcb();
                }

                keys.data.forEach(key => {  
                    const currentKeyVersion = keyVersions.data.find(version => version.id === key.currentKeyVersion);

                    let timeCreated = currentKeyVersion ? currentKeyVersion.timeCreated : key.timeCreated;
                    var diffInDays = helpers.daysBetween(timeCreated, new Date());
        
                    if (diffInDays > keyRotationInterval) {
                        helpers.addResult(results, 2,
                            `Cryptographic Key was last rotated ${diffInDays} days ago which is greater than ${keyRotationInterval}`, region, key.id);
                    } else {
                        helpers.addResult(results, 0,
                            `Cryptographic Key was last rotated ${diffInDays} days ago which is equal to or less than ${keyRotationInterval}`, region, key.id);
                    }
                });

                
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
