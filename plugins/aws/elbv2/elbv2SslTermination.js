var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELB SSL Termination',
    category: 'ELBv2',
    domain: 'Content Delivery',
    description: 'Ensure that Load Balancers has SSL certificate configured for SSL terminations.',
    more_info: 'SSL termination or SSL offloading decrypts and verifies data on the load balancer instead of the application server which spares the server of having to organize incoming connections and prioritize on other tasks like loading web pages. This helps increase server speed.',
    link: 'https://aws.amazon.com/blogs/aws/elastic-load-balancer-support-for-ssl-termination/',
    recommended_action: 'Attach SSL certificate with the listener to AWS Elastic Load Balancer',
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
                    `Unable to query for Load Balancers: ${helpers.addError(describeLoadBalancers)}`,
                    region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No Load Balancers found', region);
                return rcb();
            }

            async.each(describeLoadBalancers.data, function(elb, cb){
                var resource = elb.LoadBalancerArn;

                var describeListeners = helpers.addSource(cache, source,
                    ['elbv2', 'describeListeners', region, elb.DNSName]);

                if (!describeListeners || describeListeners.err || !describeListeners.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for Load Balancer listeners: ${helpers.addError(describeListeners)}`,
                        region, resource);
                    return cb();
                }

                if (!describeListeners.data.Listeners || !describeListeners.data.Listeners.length){
                    helpers.addResult(results, 2,
                        'No Load Balancer listeners found',
                        region, resource);
                    return cb();
                }

                let found = !!describeListeners.data.Listeners.find(listener => listener.Certificates && listener.Certificates.length);
    
                if (found) {
                    helpers.addResult(results, 0,
                        'Elastic Load Balancer has SSL Termination configured',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Elastic Load Balancer does not have SSL Termination configured',
                        region, resource);
                }

                cb();
            }, function(){
                rcb();
            });

        }, function(){
            callback(null, results, source);
        });
    }
};
