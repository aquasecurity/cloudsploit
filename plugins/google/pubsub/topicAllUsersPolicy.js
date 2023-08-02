var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Topic All Users Policy',
    category: 'Pub/Sub',
    domain: 'Application Integration',
    description: 'Ensure Pub/Sub Topics are not anonymously or publicly accessible',
    more_info: 'Cloud IAM policy governs the access permissions to pub/sub topics. Granting anonymous or public access to pub/sub topics is risky if you are storing any sensitive messages. As a best practice, limit the access to specific authenticated users or groups or service accounts.',
    link: 'https://cloud.google.com/pubsub/docs/access-control',
    recommended_action: 'Ensure that each pub/sub topic is configured so that no member is set to allUsers or allAuthenticatedUsers.',
    apis: ['topics:list','topics:getIamPolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.topics, function(region, rcb){
            let topics = helpers.addSource(
                cache, source, ['topics', 'list', region]);

            if (!topics) return rcb();

            if (topics.err || !topics.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Pub/Sub topics: ' + helpers.addError(topics), region, null, null, topics.err);
                return rcb();
            }
        
            if (!topics.data.length) {
                helpers.addResult(results, 0, 'No Pub/Sub topics found', region);
                return rcb();
            }

            let topicPolicies = helpers.addSource(cache, source,
                ['topics', 'getIamPolicy', region]);

            if (!topicPolicies) return rcb();

            if (topicPolicies.err || !topicPolicies.data) {
                helpers.addResult(results, 3, 'Unable to query topic policies: ' + helpers.addError(topicPolicies), region, null, null, topicPolicies.err);
                return rcb();
            }

            if (!topicPolicies.data.length) {
                helpers.addResult(results, 0, 'No Pub/Sub topics found', region);
                return rcb();
            }

            topics.data.forEach(topic => {
                let topicPolicy = topicPolicies.data.find(policy => policy.parent && policy.parent.name && policy.parent.name === topic.name);
                let hasAllUsers = false;
                if (topicPolicy.bindings &&
                    topicPolicy.bindings.length) {
                    topicPolicy.bindings.forEach(binding => {
                        if (binding.members &&
                           binding.members.length) {
                            binding.members.forEach(member => {
                                if (member === 'allUsers' ||
                                   member === 'allAuthenticatedUsers') {
                                    hasAllUsers = true;
                                }
                            });
                        }
                    });
                }
                if (hasAllUsers) {
                    helpers.addResult(results, 2,
                        'Pub/Sub topic has anonymous or public access', region, topic.name);
                } else {
                    helpers.addResult(results, 0,
                        'Pub/Sub topic does not have anonymous or public access', region, topic.name);
                }
               
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};