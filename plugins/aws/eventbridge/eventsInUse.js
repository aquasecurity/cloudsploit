var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS CloudWatch Events In Use',
    category: 'EventBridge',
    domain: 'Management and Governance',
    description: 'Ensure that Amazon CloudWatch Events service is in use in order to enable you to react selectively and efficiently to system events.',
    more_info: 'Amazon CloudWatch Events delivers a near real-time stream of system events that describe changes in Amazon Web Services (AWS) resources. Using simple rules that you can quickly set up, you can match events and route them to one or more target functions or streams.',
    link: 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/WhatIsCloudWatchEvents.html',
    recommended_action: 'Check if CloudWatch events are in use or not by observing the data received.',
    apis: ['EventBridge:listRules'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var listRules = helpers.addSource(cache, source,
            ['eventbridge', 'listRules', region]);

        if (!listRules) return callback(null, results, source);

        if (listRules.err || !listRules.data) {
            helpers.addResult(results, 3,
                'Unable to list CloudWatch events rules: ' + helpers.addError(listRules), region);
            return callback(null, results, source);
        }

        if (listRules.data.length) {
            helpers.addResult(results, 0, 
                'AWS CloudWatch events are currently in use', 
                region);
        } else {
            helpers.addResult(results, 2,
                'AWS CloudWatch events are not currently in use', 
                region);
        }

        return callback(null, results, source);
    }
};
