var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Topic Encryption Enabled',
    category: 'Pub/Sub',
    description: 'Ensure that Google Pub/Sub topics are ecnrypted on desired encryption level.',
    more_info: 'Google encrypts all messages in topics by default. By using CSEK, only the users with the key can access the disk. Anyone else, including Google, cannot access the disk data.',
    link: 'https://cloud.google.com/pubsub/docs/encryption',
    recommended_action: 'Ensure that Cloud Pub/Sub topics are encrypted using CSEK keys',
    apis: ['topics:list'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
            'Enabling encryption for Pub/Sub topics helps to protect this data.',
        pci: 'PCI requires proper encryption of cardholder data at rest. ' +
            'Encryption should be enabled for all topics storing this ' +
            'type of data.'
    },
    settings: {
        pubsub_topic_encryption: {
            name: 'Pub/Sub Topic Encryption Protection Level',
            description: 'Desired protection level for Pub/Sub topics. defualt: google-managed, cloudcmek: customer managed encryption keys, ' +
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
            desiredEncryptionLevelStr: settings.pubsub_topic_encryption || this.settings.pubsub_topic_encryption.default
        };

        var desiredEncryptionLevel = helpers.PROTECTION_LEVELS.indexOf(desiredEncryptionLevelStr);

        async.each(regions.topics, function(region, rcb){
            var topics = helpers.addSource(cache, source,
                ['topics', 'list', region]);

            if (!topics) return rcb();

            if ((topics.err && topics.err.length > 0) || !topics.data) {
                helpers.addResult(results, 3,
                    'Unable to query for log topics: ' + helpers.addError(topics), region, null, null, topics.err);
                return rcb();
            }

            if (!topics.data.length > 0) {
                helpers.addResult(results, 2, 'No log topics found', region);
                return rcb();
            }

            async.each(topics.data, (topic, tcp) => {
                let currentEncryptionLevel;
                if (topic.kmsKeyName && topic.kmsKeyName.length) {

                } else {
                    currentEncryptionLevel = 1; //default
                }
            });
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};




