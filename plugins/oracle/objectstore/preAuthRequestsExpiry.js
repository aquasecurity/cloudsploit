var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Pre-Authenticated Requests Expiry',
    category: 'Object Store',
    description: 'Ensure that pre-authenticated requests expire within a certain time.',
    more_info: 'Pre-authenticated requests allow for users who are not in the tenancy to access buckets, having a short expiration time-frame ensures that access does not last longer than intended.',
    recommended_action: 'When creating pre-authenticated Requests, ensure the expiration date-time is limited to the minimum time possible.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Object/Tasks/usingPre-Authenticatedrequests.htm',
    apis: ['bucket:list','preAuthenticatedRequest:list'],
    settings: {
        preauthorization_expiration_date_warn: {
            name: 'Pre-Authorization Request Expiration Date Warning',
            description: 'Return a warning result when pre-authorization Expiration date passes threshold',
            regex: '^(365|[1-9][1-9][0-9]?)$',
            default: 10
        },
        preauthorization_expiration_date_fail: {
            name: 'Pre-Authorization Request Expiration Date Fail',
            description: 'Return a failing result when pre-authorization Expiration date passes threshold',
            regex: '^(365|[1-9][1-9][0-9]?)$',
            default: 30
        },
    },
    
    run: function(cache, settings, callback) {
        var config = {
            preauthorization_expiration_date_warn: settings.preauthorization_expiration_date_warn || this.settings.preauthorization_expiration_date_warn.default,
            preauthorization_expiration_date_fail: settings.preauthorization_expiration_date_fail || this.settings.preauthorization_expiration_date_fail.default,
        };
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.preAuthenticatedRequest, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var requests = helpers.addSource(cache, source,
                    ['preAuthenticatedRequest', 'list', region]);

                if (!requests) return rcb();

                if ((requests.err && requests.err.length) || !requests.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for pre-authenticated requests: ' + helpers.addError(requests), region);
                    return rcb();
                }

                if (!requests.data.length) {
                    helpers.addResult(results, 0, 'No pre-authenticated requests found', region);
                    return rcb();
                }

                var expiredRequests = true;
                var shortExpiry = true;
                requests.data.forEach(request => {
                    if (request.timeExpires) {
                        var ONE_DAY = 24*60*60*1000;
                        var timeExpires = request.timeExpires.split("T")[0];

                        timeExpires = Math.ceil((new Date(timeExpires).getTime() - new Date(new Date()).getTime())/(ONE_DAY));

                        if (timeExpires < 0) return;

                        expiredRequests = false;
                    }
                    if (timeExpires > config.preauthorization_expiration_date_fail) {
                        helpers.addResult(results, 2,
                            `pre-authenticated request expires in ${timeExpires} days`, region, request.id);
                        shortExpiry = false;
                    } else if (timeExpires > config.preauthorization_expiration_date_warn) {
                        helpers.addResult(results, 1,
                            `pre-authenticated request expires in ${timeExpires} days`, region, request.id);
                        shortExpiry = false;
                    }
                });
                if (expiredRequests) {
                    helpers.addResult(results, 0, 'No active pre-authenticated requests', region);
                } else if (shortExpiry) {
                    helpers.addResult(results, 0,
                        `All pre-authenticated requests are set to expire in less than ${config.preauthorization_expiration_date_warn} days`, region);
                }
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};