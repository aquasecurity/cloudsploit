var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SNS Topic Encrypted',
    category: 'SNS',
    description: 'Ensures that Amazon SNS topics enforce Server-Side Encryption (SSE)',
    more_info: 'SNS topics should enforce Server-Side Encryption (SSE) to secure data at rest. SSE protects the contents of messages in Amazon SNS topics using keys managed in AWS Key Management Service (AWS KMS).',
    recommended_action: 'Enable Server-Side Encryption to protect the content of SNS topic messages.',
    link: 'https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html',
    apis: ['SNS:listTopics', 'SNS:getTopicAttributes'],
    remediation_description: 'Server-Side Encryption to protect the content of SNS topic messages will be enabled.',
    remediation_min_version: '202011182332',
    apis_remediate: ['SNS:listTopics', 'SNS:getTopicAttributes'],
    remediation_inputs: {
        kmsKeyIdforSns: {
            name: '(Optional) KMS Key ID',
            description: 'The KMS Key ID used for encryption',
            regex: '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$',
            required: false
        }
    },
    actions: {
        remediate: ['SNS:setTopicAttributes'],
        rollback: ['SNS:setTopicAttributes']
    },
    permissions: {
        remediate: ['sns:SetTopicAttributes'],
        rollback: ['sns:SetTopicAttributes']
    },
    realtime_triggers: ['sns:CreateTopic', 'sns:SetTopicAttributes'],

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
                var accountId = resource.split(':')[4];
                var cloudsploitSNS = helpers.CLOUDSPLOIT_EVENTS_SNS + accountId;

                if( resource.indexOf(cloudsploitSNS) > -1){
                    helpers.addResult(results, 0,
                        'This SNS topic is auto-allowed as part of a cross-account notification topic used by the real-time events service',
                        region, resource);
                    return cb();
                }
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
                    helpers.addResult(results, 0,
                        'Server-Side Encryption is enabled for SNS topic',
                        region, resource);
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
    },

    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'topicEncrypted';
        var topicNameArr = resource.split(':');
        var topicName = topicNameArr[topicNameArr.length - 1];

        // find the location of the topic needing to be remediate
        var topicLocation = topicNameArr[3];
        // add the location of the topic to the config
        config.region = topicLocation;
        var params = {};
        // create the params necessary for the remediation
        if (settings.input &&
            settings.input.kmsKeyIdforSns) {
            params = {
                AttributeName: 'KmsMasterKeyId',
                TopicArn: resource,
                AttributeValue: settings.input.kmsKeyIdforSns
            };
        } else {
            params = {
                AttributeName: 'KmsMasterKeyId',
                TopicArn: resource,
                AttributeValue: 'alias/aws/sns'
            };
        }

        var remediation_file = settings.remediation_file;

        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'Encryption': 'Disabled',
            'Topic': topicName
        };

        // passes the config, put call, and params to the remediate helper function
        helpers.remediatePlugin(config, putCall[0], params, function(err) {
            if (err) {
                remediation_file['remediate']['actions'][pluginName]['error'] = err;
                return callback(err, null);
            }

            let action = params;
            action.action = putCall;

            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'ENCRYPTED',
                'Topic': topicName
            };
            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    },

    rollback: function(config, cache, settings, resource, callback) {
        console.log('Rollback support for this plugin has not yet been implemented');
        console.log(config, cache, settings, resource);
        callback();
    }
};