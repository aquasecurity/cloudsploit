var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELB Logging Enabled',
    category: 'ELB',
    description: 'Ensures load balancers have request logging enabled.',
    more_info: 'Logging requests to ELB endpoints is a helpful way ' + 
                'of detecting and investigating potential attacks, ' + 
                'malicious activity, or misuse of backend resources.' + 
                'Logs can be sent to S3 and processed for further ' +
                'analysis.',
    link: 'http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html',
    recommended_action: 'Enable ELB request logging',
    apis: ['ELB:describeLoadBalancers', 'ELB:describeLoadBalancerAttributes', 'STS:getCallerIdentity'],
    compliance: {
        hipaa: 'HIPAA requires access logging to be enabled for the auditing ' +
                'of services serving HIPAA data. All ELBs providing this access ' +
                'should have logging enabled to deliver logs to a secure remote ' +
                'location.',
        pci: 'PCI requires logging of all network access to environments containing ' +
             'cardholder data. Enable ELB logs to log these network requests.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.elb, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elb', 'describeLoadBalancers', region]);

            if (!describeLoadBalancers) return rcb();

            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for load balancers: ' + helpers.addError(describeLoadBalancers), region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No load balancers present', region);
                return rcb();
            }

            async.each(describeLoadBalancers.data, function(lb, cb){
                // arn:aws:elasticloadbalancing:region:account-id:loadbalancer/name
                var elbArn = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;

                // loop through listeners
                var describeLoadBalancerAttributes = helpers.addSource(cache, source,
                    ['elb', 'describeLoadBalancerAttributes', region, lb.DNSName]);

                if ( describeLoadBalancerAttributes.data && 
                    describeLoadBalancerAttributes.data.LoadBalancerAttributes && 
                    describeLoadBalancerAttributes.data.LoadBalancerAttributes.AccessLog) {
                    var accessLog = describeLoadBalancerAttributes.data.LoadBalancerAttributes.AccessLog;
                    
                    if (accessLog.Enabled){
                        helpers.addResult(results, 0,
                            'Logging enabled for ' + lb.DNSName, region, elbArn);
                    } else {
                        helpers.addResult(results, 2,
                            'Logging not enabled for ' + lb.DNSName, region, elbArn);
                    }
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
