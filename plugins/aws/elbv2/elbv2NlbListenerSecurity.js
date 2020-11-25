var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 NLB Listener Security',
    category: 'ELBv2',
    description: 'Ensures that AWS Network Load Balancers have secured listener configured.',
    more_info: 'AWS Network Load Balancer should have TLS protocol listener configured to terminate TLS traffic.',
    link: 'https://docs.amazonaws.cn/en_us/elasticloadbalancing/latest/network/create-tls-listener.html',
    recommended_action: 'Attach TLS listener to AWS Network Load Balancer',
    apis: ['ELBv2:describeLoadBalancers', 'ELBv2:describeListeners'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.elbv2, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elbv2', 'describeLoadBalancers', region]);

            if (!describeLoadBalancers) return rcb();

            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Network Load Balancers: ${helpers.addError(describeLoadBalancers)}`,
                    region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No Load Balancers found', region);
                return rcb();
            }

            var networkElbFound = false;
            async.each(describeLoadBalancers.data, function(elb, cb){
                if (elb.Type && elb.Type === 'network') {
                    networkElbFound = true;
                    var securedListenerFound = false;
                    var resource = elb.LoadBalancerArn;

                    var describeListeners = helpers.addSource(cache, source,
                        ['elbv2', 'describeListeners', region, elb.DNSName]);

                    if (!describeListeners || describeListeners.err || !describeListeners.data) {
                        helpers.addResult(results, 3,
                            `Unable to query for Network Load Balancer listeners: ${helpers.addError(describeListeners)}`,
                            region, resource);
                        return cb();
                    }

                    if(!describeListeners.data.Listeners || !describeListeners.data.Listeners.length){
                        helpers.addResult(results, 2,
                            'No Network Load Balancer listeners found',
                            region, resource);
                        return cb();
                    }

                    for (var l in describeListeners.data.Listeners) {
                        var listener = describeListeners.data.Listeners[l];
                        if(listener.Protocol && listener.Protocol === 'TLS') {
                            securedListenerFound = true;
                            break;
                        }
                    }

                    if(securedListenerFound) {
                        helpers.addResult(results, 0,
                            'Network Load Balancer has secure listener configured',
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Network Load Balancer does not have secure listener configured',
                            region, resource);
                    }
                }

                cb();
            });

            if (!networkElbFound) {
                helpers.addResult(results, 0,
                    'No Network Load Balancers found', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};