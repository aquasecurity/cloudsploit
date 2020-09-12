var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SNS Topic Encrypted With KMS Customer Master Keys',
    category: 'SNS',
    description: 'Ensure that Amazon SNS topics are encrypted with KMS Customer Master Keys (CMKs).',
    more_info: 'SNS topics should enforce Server-Side Encryption (SSE) with Customer Master Keys (CMKs) to secure data at rest. SSE protects the contents of messages in Amazon SNS topics using keys managed in AWS Key Management Service (AWS KMS).',
    recommended_action: 'Use Customer Master Keys (CMKs) for Server-Side Encryption to protect the conents of SNS topic messages.',
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
                var resource = topic.TopicArn;
                if (!resource) return cb();

                var getTopicAttributes = helpers.addSource(cache, source,
                    ['sns', 'getTopicAttributes', region, resource]);

                if (!getTopicAttributes ||
                    (!getTopicAttributes.err && !getTopicAttributes.data)) return cb();

                if (getTopicAttributes.err || !getTopicAttributes.data) {
                    helpers.addResult(results, 3,
                        'Unable to query SNS topic for policy: ' + helpers.addError(getTopicAttributes),
                        region, resource);

                    return cb();
                }

                if (getTopicAttributes.data.Attributes &&
                    getTopicAttributes.data.Attributes.KmsMasterKeyId) {
                    var kmsMasterKeyId = getTopicAttributes.data.Attributes.KmsMasterKeyId;
                    if (kmsMasterKeyId === 'alias/aws/sns'){
                        helpers.addResult(results, 2,
                            'The SNS topic has Server-Side Encryption enabled with default KMS key',
                            region, resource);
                    }
                    else {
                        helpers.addResult(results, 0,
                            'The SNS topic has Server-Side Encryption enabled with KMS Customer Master key',
                            region, resource);
                    }
                }
                else {
                    helpers.addResult(results, 2,
                        'The SNS topic does not have Server-Side Encryption enabled',
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