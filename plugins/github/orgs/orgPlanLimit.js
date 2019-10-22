var async = require('async');
var helpers = require('../../../helpers/github');

module.exports = {
    title: 'Org Plan Limit',
    types: ['org'],
    category: 'Orgs',
    description: 'Checks that the number of seats is not close to the limit of available licensed seats.',
    more_info: 'Running out of licenses will prevent developers from adding new users.',
    link: 'https://developer.github.com/v3/orgs/#get-an-organization',
    recommended_action: 'Remove unused users or update GitHub payment plan to support more licensed seats.',
    apis: ['orgs:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var getOrg = helpers.addSource(cache, source,
            ['orgs', 'get']);

        if (!getOrg) return callback(null, results, source);

        if (getOrg.err || !getOrg.data) {
            helpers.addResult(results, 3,
                'Unable to query for organization plan information: ' + helpers.addError(getOrg));
            return callback(null, results, source);
        }

        if (!getOrg.data.plan) {
            helpers.addResult(results, 3, 'GitHub plan information was not present in API response. Ensure token is authorized to access.');
            return callback(null, results, source);
        }

        var plan = getOrg.data.plan;

        if (typeof(plan.filled_seats) !== 'undefined' && typeof(plan.seats) !== 'undefined') {
            // Handle grandfathered plans that didn't assign seats
            if (plan.seats == 0) {
                helpers.addResult(results, 0, 'GitHub plan is grandfathered into unlimited seats');
                return callback(null, results, source);
            }

            var percentUsed = Math.ceil((plan.filled_seats/plan.seats)*100);
            var result = 0;
            
            if (percentUsed >= 90) {
                result = 2;
            } else if (percentUsed >= 80) {
                result = 1;
            }

            helpers.addResult(results, result, 'Org is currently using ' + plan.filled_seats + ' out of ' + plan.seats + ' available seats.');
        } else {
            helpers.addResult(results, 3, 'GitHub plan information did not contain licensed plan information.');
            return callback(null, results, source);
        }

        callback(null, results, source);
    }
};