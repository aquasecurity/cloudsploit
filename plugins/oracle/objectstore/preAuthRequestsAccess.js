var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Pre-Authenticated Requests Access',
    category: 'Object Store',
    description: 'Ensure that Pre-Authenticated Requests have least privilege access.',
    more_info: 'PreAuthenticated requests allow for users who are not in the tenancy to access buckets, ensuring least access prevents malicious entities from leveraging this type of access to edit or delete objects in a bucket.',
    recommended_action: 'When creating Pre-Authenticated Requests, ensure only ObjectRead permissions are selected.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Object/Tasks/usingpreauthenticatedrequests.htm',
    apis: ['bucket:list','preAuthenticatedRequest:list'],

    run: function(cache, settings, callback) {
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
                var leastAccess = true;
                requests.data.forEach(request => {
                    var ONE_DAY = 24*60*60*1000;
                    var myTimeExpires = request.timeExpires.split("T")[0];

                    myTimeExpires = Math.ceil((new Date(myTimeExpires).getTime() - new Date(new Date()).getTime())/(ONE_DAY));

                    if (myTimeExpires < 0) return;

                    expiredRequests = false;

                    if (request.accessType &&
                        ((request.accessType == 'AnyObjectWrite'))) {
                        helpers.addResult(results, 2,
                            'Pre-Authenticated request allows write access to all objects', region, request.id);
                        leastAccess = false;
                    } else if (request.accessType &&
                            (!(request.accessType == 'ObjectRead'))) {
                        helpers.addResult(results, 1,
                            `Pre-Authenticated request allows write access to ${request.objectName}`, region, request.id);
                        leastAccess = false;
                    };
                });
                if (expiredRequests) {
                    helpers.addResult(results, 0, 'No active Pre-Authenticated requests', region);
                } else if (leastAccess) {
                    helpers.addResult(results, 0, 'All Pre-Authenticated requests have least access', region);
                }
            };
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};