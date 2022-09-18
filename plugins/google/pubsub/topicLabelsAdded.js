var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Topic Labels Added',
    category: 'Pub/Sub',
    domain: 'Application Integration',
    description: 'Ensure that all Pub/Sub topics have labels added.',
    more_info: 'Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/pubsub/docs/labels',
    recommended_action: 'Ensure labels are added to all Pub/Sub topics.',
    apis: ['topics:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.topics, function(region, rcb){
            let topics = helpers.addSource(cache, source,
                ['topics', 'list', region]);

            if (!topics) return rcb();

            if (topics.err || !topics.data) {
                helpers.addResult(results, 3, 'Unable to query Pub/Sub topics', region, null, null, topics.err);
                return rcb();
            }

            if (!topics.data.length) {
                helpers.addResult(results, 0, 'No Pub/Sub topics found', region);
                return rcb();
            }

            topics.data.forEach(topic => {
                if (topic.labels &&
                    Object.keys(topic.labels).length) {
                    helpers.addResult(results, 0,
                        `${Object.keys(topic.labels).length} labels found for Pub/Sub topic`, region, topic.name);
                } else {
                    helpers.addResult(results, 2,
                        'Pub/Sub topic does not have any labels', region, topic.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
