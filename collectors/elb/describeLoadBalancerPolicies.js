// TODO: re-visit this one

var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
	var elb = new AWS.ELB(AWSConfig);

	// Gather list of policies from load balancers
	var policies = [];

	for (i in collection.elb.describeLoadBalancers[AWSConfig.region].data) {
		var lb = collection.elb.describeLoadBalancers[AWSConfig.region].data[i];

		for (j in lb.ListenerDescriptions) {
			var lsDescs = lb.ListenerDescriptions[j];

			if (lsDescs.Listener.Protocol === 'HTTPS') {
				var elbPolicies = [];
				for (k in lsDescs.PolicyNames) {
					elbPolicies.push(lsDescs.PolicyNames[k]);
				}
				if (elbPolicies.length) {
					var elbObj = {
						LoadBalancerName: lb.LoadBalancerName,
						LoadBalancerDNS: lb.DNSName,
						PolicyNames: elbPolicies
					};
					policies.push(elbObj);
				}
			}
		}
	}

	if (!policies.length) {
		results.push({
			status: 0,
			message: 'No load balancers are using HTTPS',
			region: region
		});

		return rcb();
	}

	async.eachLimit(policies, 15, function(policy, cb){
		elb.describeLoadBalancerPolicies({LoadBalancerName: policy.LoadBalancerName, PolicyNames:policy.PolicyNames}, function(err, data){
			if (err || !data || !data.PolicyDescriptions) {
				results.push({
					status: 3,
					message: 'Unable to query load balancer policies for ELB: ' + policy.LoadBalancerName,
					region: region,
					resource: policy.LoadBalancerDNS,
				});
				return cb();
			}

			for (i in data.PolicyDescriptions) {
				var elbBad = [];
				for (j in data.PolicyDescriptions[i].PolicyAttributeDescriptions) {
					if (data.PolicyDescriptions[i].PolicyAttributeDescriptions[j].AttributeValue === 'true' && badCiphers.indexOf(data.PolicyDescriptions[i].PolicyAttributeDescriptions[j].AttributeName) > -1) {
						elbBad.push(data.PolicyDescriptions[i].PolicyAttributeDescriptions[j].AttributeName);
					}
				}
				if (elbBad.length) {
					results.push({
						status: 1,
						message: 'ELB: ' + policy.LoadBalancerName + ' uses insecure protocols or ciphers: ' + elbBad.join(', '),
						region: region,
						resource: policy.LoadBalancerDNS,
					});
				} else {
					results.push({
						status: 0,
						message: 'ELB: ' + policy.LoadBalancerName + ' uses secure protocols and ciphers',
						region: region,
						resource: policy.LoadBalancerDNS,
					});
				}
			}
			cb();
		});
	}, function(){
		rcb();
	});
};