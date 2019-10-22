var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Pre-Authenticated Requests Expiry',
    category: 'Object Store',
    description: 'Ensure that Pre-Authenticated Requests expire within a certain time.',
    more_info: 'Pre-Authenticated requests allow for users who are not in the tenancy to access buckets, having a short expiration time-frame ensures that access does not last longer than intended.',
    recommended_action: 'When creating Pre-Authenticated Requests, ensure the expiration date-time is limited to the minimum time possible.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Object/Tasks/usingPre-Authenticatedrequests.htm',
    apis: ['bucket:list','preAuthenticatedRequest:list'],
    settings: {
        preauthorization_expiration_date_warn: {
            name: 'PreAuthorization Request Expiration Date Warning',
            description: 'Return a warning result when PreAuthorization Expiration date passes threshold',
            regex: '^(365|[1-9][1-9][0-9]?)$',
            default: 10
        },
        preauthorization_expiration_date_fail: {
            name: 'PreAuthorization Request Expiration Date Fail',
            description: 'Return a failing result when PreAuthorization Expiration date passes threshold',
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
                        'Unable to query for Pre-Authenticated requests: ' + helpers.addError(requests), region);
                    return rcb();
                };

                if (!requests.data.length) {
                    helpers.addResult(results, 0, 'No Pre-Authenticated requests present', region);
                    return rcb();
                };

                var expiredRequests = true;
                var shortExpiry = true;
                requests.data.forEach(request => {
                    var ONE_DAY = 24*60*60*1000;
                    var myTimeExpires = request.timeExpires.split("T")[0];

                    myTimeExpires = Math.ceil((new Date(myTimeExpires).getTime() - new Date(new Date()).getTime())/(ONE_DAY));

                    if (myTimeExpires < 0) return;

                    expiredRequests = false;
                    if (myTimeExpires > config.preauthorization_expiration_date_fail) {
                        helpers.addResult(results, 2,
                            `Pre-Authenticated request expires in ${myTimeExpires} days`, region, request.id);
                        shortExpiry = false;
                    } else if (myTimeExpires > config.preauthorization_expiration_date_warn) {
                        helpers.addResult(results, 1,
                            `Pre-Authenticated request expires in ${myTimeExpires} days`, region, request.id);
                        shortExpiry = false;
                    };
                });
                if (expiredRequests) {
                    helpers.addResult(results, 0, 'No active Pre-Authenticated requests', region);
                } else if (shortExpiry) {
                    helpers.addResult(results, 0,
                        `All Pre-Authenticated requests are set to expire in less than ${config.preauthorization_expiration_date_warn} days`, region);
                }
            };
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};