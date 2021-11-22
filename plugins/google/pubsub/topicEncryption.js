var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Topic Encryption Enabled',
    category: 'Pub/Sub',
    domain: 'Application Integration',
    description: 'Ensure that Google Pub/Sub topics are encrypted with desired encryption level.',
    more_info: 'Google encrypts all messages in topics by default. By using CSEK, only the users with the key can access the disk. Anyone else, including Google, cannot access the disk data.',
    link: 'https://cloud.google.com/pubsub/docs/encryption',
    recommended_action: 'Ensure that Cloud Pub/Sub topics are encrypted using CSEK keys',
    apis: ['topics:list', 'keyRings:list','cryptoKeys:list'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
            'Enabling encryption for Pub/Sub topics helps to protect this data.',
        pci: 'PCI requires proper encryption of cardholder data at rest. ' +
            'Encryption should be enabled for all topics storing this ' +
            'type of data.'
    },
    settings: {
        pubsub_topic_encryption_level: {
            name: 'Pub/Sub Topic Encryption Protection Level',
            description: 'Desired protection level for Pub/Sub topics. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM ecnryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        var config = {
            desiredEncryptionLevelStr: settings.pubsub_topic_encryption_level || this.settings.pubsub_topic_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.PROTECTION_LEVELS.indexOf(config.desiredEncryptionLevelStr);

        var keysObj = {};

        async.series([
            function(cb){
                async.each(regions.cryptoKeys, function(region, rcb){
                    let cryptoKeys = helpers.addSource(
                        cache, source, ['cryptoKeys', 'list', region]);

                    if (cryptoKeys && cryptoKeys.data && cryptoKeys.data.length) helpers.listToObj(keysObj, cryptoKeys.data, 'name');
                    rcb();
                }, function(){
                    cb();
                });
            },
            function(cb){
                async.each(regions.topics, function(tregion, trcb){
                    var topics = helpers.addSource(cache, source,
                        ['topics', 'list', tregion]);

                    if (!topics) return trcb();
                
                    if (topics.err || !topics.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for Pub/Sub topics: ' + helpers.addError(topics), tregion, null, null, topics.err);
                        return trcb();
                    }
                
                    if (!topics.data.length) {
                        helpers.addResult(results, 0, 'No Pub/Sub topics found', tregion);
                        return trcb();
                    }
    
                    async.each(topics.data, (topic, tcp) => {
                        let currentEncryptionLevel;
                        if (topic.kmsKeyName && topic.kmsKeyName.length && keysObj[topic.kmsKeyName]) {
                            currentEncryptionLevel = helpers.getProtectionLevel(keysObj[topic.kmsKeyName], helpers.PROTECTION_LEVELS);
                        } else {
                            currentEncryptionLevel = 1; //default
                        }
    
                        let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];
                        if (currentEncryptionLevel >= desiredEncryptionLevel) {
                            helpers.addResult(results, 0,
                                `Pub/Sub topic is encrypted with ${currentEncryptionLevelStr} which is greater than or equal to ${config.desiredEncryptionLevelStr}`,
                                tregion, topic.name);
                        } else {
                            helpers.addResult(results, 2,
                                `Pub/Sub topic is encrypted with ${currentEncryptionLevelStr} which is less than ${config.desiredEncryptionLevelStr}`,
                                tregion, topic.name);
                        }
    
                        tcp();
                    }, function(){
                        trcb();
                    });
                }, function(){
                    cb();
                });
            }
        ], function(){
            callback(null, results, source);
        });
    }
};
                
