var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Shield Emergency Contacts',
    category: 'Shield',
    description: 'Ensures AWS Shield emergency contacts are configured',
    more_info: 'AWS Shield Emergency contacts should be configured so that AWS can contact an account representative in the event of a DDOS event.',
    recommended_action: 'Configure emergency contacts within AWS Shield for the account.',
    link: 'https://docs.aws.amazon.com/waf/latest/developerguide/ddos-edit-drt.html',
    apis: ['Shield:describeEmergencyContactSettings'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var describeEmergencyContactSettings = helpers.addSource(cache, source,
            ['shield', 'describeEmergencyContactSettings', region]);

        if (!describeEmergencyContactSettings) return callback(null, results, source);

        if (describeEmergencyContactSettings.err &&
            describeEmergencyContactSettings.err.code &&
            describeEmergencyContactSettings.err.code == 'ResourceNotFoundException') {
            helpers.addResult(results, 2, 'Shield subscription is not enabled');
            return callback(null, results, source);
        }

        if (describeEmergencyContactSettings.err || !describeEmergencyContactSettings.data) {
            helpers.addResult(results, 3,
                'Unable to query for Shield emergency contacts: ' + helpers.addError(describeEmergencyContactSettings));
            return callback(null, results, source);
        }

        if (!describeEmergencyContactSettings.data.length) {
            helpers.addResult(results, 2, 'Shield emergency contacts are not configured');
        } else {
            helpers.addResult(results, 0, 'Shield emergency contacts are configured with: ' + describeEmergencyContactSettings.data.length + ' contacts');
        }

        return callback(null, results, source);
    }
};