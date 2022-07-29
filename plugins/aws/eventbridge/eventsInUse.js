var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EventBridge Event Rules In Use',
    category: 'EventBridge',
    domain: 'Management and Governance',
    severity: 'LOW',
    description: 'Ensure that Amazon EventBridge Events service is in use in order to enable you to react selectively and efficiently to system events.',
    more_info: 'Amazon EventBridge Events delivers a near real-time stream of system events that describe changes in Amazon Web Services (AWS) resources. Using simple rules that you can quickly set up, you can match events and route them to one or more target functions or streams.',
    link: 'https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html',
    recommended_action: 'Create EventBridge event rules to meet regulatory and compliance requirement within your organization.',
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
                'Unable to list EventBridge event rules: ' + helpers.addError(listRules), region);
            return callback(null, results, source);
        }

        if (listRules.data.length) {
            helpers.addResult(results, 0, 
                'EventBridge event rules are in use', 
                region);
        } else {
            helpers.addResult(results, 2,
                'EventBridge event rules are not in use', 
                region);
        }

        return callback(null, results, source);
    }
};
