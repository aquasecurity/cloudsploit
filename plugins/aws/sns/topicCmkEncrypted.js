var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SNS Topic CMK Encryption',
    category: 'SNS',
    description: 'Ensures Amazon SNS topics are encrypted with KMS Customer Master Keys (CMKs).',
    more_info: 'AWS SNS topics should be  encrypted with KMS Customer Master Keys (CMKs) instead of AWS managed-keys' +
               'in order to have a more granular control over the SNS data-at-rest encryption and decryption process.',
    recommended_action: 'Update SNS topics to use Customer Master Keys (CMKs) for Server-Side Encryption.',
    link: 'https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html',
    apis: ['SNS:listTopics', 'SNS:getTopicAttributes'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.sns, function(region, rcb){
            var listTopics = helpers.addSource(cache, source,
                ['sns', 'listTopics', region]);

            if (!listTopics) return rcb();

            if (listTopics.err || !listTopics.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SNS topics: ' + helpers.addError(listTopics), region);
                return rcb();
            }

            if (!listTopics.data.length) {
                helpers.addResult(results, 0, 'No SNS topics found', region);
                return rcb();
            }

            async.each(listTopics.data, function(topic, cb){
                if (!topic.TopicArn) return cb();
                
                var resource = topic.TopicArn;

                var getTopicAttributes = helpers.addSource(cache, source,
                    ['sns', 'getTopicAttributes', region, resource]);

                if (!getTopicAttributes || getTopicAttributes.err || !getTopicAttributes.data) {
                    helpers.addResult(results, 3,
                        'Unable to query SNS topic attributes: ' + helpers.addError(getTopicAttributes),
                        region, resource);

                    return cb();
                }

                if (getTopicAttributes.data.Attributes &&
                    getTopicAttributes.data.Attributes.KmsMasterKeyId) {
                    var kmsMasterKeyId = getTopicAttributes.data.Attributes.KmsMasterKeyId;
                    if (kmsMasterKeyId === 'alias/aws/sns'){
                        helpers.addResult(results, 2,
                            'SNS topic is using default KMS key for Server-Side Encryption',
                            region, resource);
                    }
                    else {
                        helpers.addResult(results, 0,
                            'SNS topic is using CMK key for Server-Side Encryption',
                            region, resource);
                    }
                }
                else {
                    helpers.addResult(results, 2,
                        'Server-Side Encryption is not enabled for SNS topic',
                        region, resource);
                }

                cb();

            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
