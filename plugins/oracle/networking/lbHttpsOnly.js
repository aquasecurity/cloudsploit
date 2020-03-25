var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Load Balancer HTTPS Only',
    category: 'Networking',
    description: 'Ensures LBs are configured to only accept ' +
                 'connections on HTTPS ports.',
    more_info: 'For maximum security, LBs can be configured to only ' +
                'accept HTTPS connections. Standard HTTP connections ' +
                'will be blocked. This should only be done if the ' +
                'client application is configured to query HTTPS ' +
                'directly and not rely on a redirect from HTTP.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managinglisteners.htm',
    recommended_action: 'Remove non-HTTPS listeners from load balancer.',
    apis: ['loadBalancer:list'],
    compliance: {
        hipaa: 'HIPAA requires that all patient information is ' +
            'encrypted at rest and in transit.',
        pci: 'PCI requires that all cardholder data is encrypted ' +
            'at rest and in transit.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
		var regions = helpers.regions(settings.govcloud);

        async.each(regions.loadBalancer, function(region, rcb){
            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var loadBalancers = helpers.addSource(cache, source,
                    ['loadBalancer', 'list', region]);

                if (!loadBalancers) return rcb();

                if (loadBalancers.err || !loadBalancers.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for load balancers: ' + helpers.addError(loadBalancers), region);
                    return rcb();
                }

                if (!loadBalancers.data.length) {
                    helpers.addResult(results, 0, 'No load balancers found', region);
                    return rcb();
                }

                async.each(loadBalancers.data, function(lb, cb) {
                    var non_https_listener = [];
                    var listenerExists = false;

                    for (let l in lb.listeners) {
                        let listener = lb.listeners[l];
                        let doesRedirect = false;
                        listenerExists = true;
                        if (listener.port !== 443 &&
                            (!listener.ruleSetNames || !listener.ruleSetNames.length)) {
                            non_https_listener.push(listener.name);
                        } else if (listener.ruleSetNames && listener.ruleSetNames.length) {
                            listener.ruleSetNames.forEach(ruleSetName => {
                                let ruleSet = lb.ruleSets[ruleSetName];
                                if (ruleSet.items && ruleSet.items.length) {
                                    ruleSet.items.forEach(ruleSetItem => {
                                        if (ruleSetItem.action && ruleSetItem.action === "REDIRECT" &&
                                            ruleSetItem.redirectUri &&
                                            ruleSetItem.redirectUri.port === 443) {
                                            doesRedirect = true
                                        }
                                    })
                                }
                            });
                            if (doesRedirect) {
                                helpers.addResult(results, 0, `The listener: ${listener.name} redirects to HTTPS`, region, lb.id);
                            }
                        } else if (listener.port === 443) {
                            helpers.addResult(results, 0, `The listener: ${listener.name} is HTTPS only`, region, lb.id);
                        }
                    }

                    if (non_https_listener.length){
                        helpers.addResult(results, 2,
                            `The following listeners are not HTTPS-only:  ${non_https_listener.join(', ')}`, region, lb.id);
                    } else if (!listenerExists) {
                        helpers.addResult(results, 0, 'No listeners found', region, lb.id);
                    }

                    cb();
                }, function() {
                    rcb();
                });
            } else {
                rcb();
            }
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};