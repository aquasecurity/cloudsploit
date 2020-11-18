var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS Route53 Dangling DNS Records',
    category: 'Route53',
    description: 'Ensure that AWS Route53 DNS records are not pointing to invalid/deleted EIPs.',
    more_info: '',
    link: '',
    recommended_action: '',
    apis: [''],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);


        callback(null, results, source);
    }
};
