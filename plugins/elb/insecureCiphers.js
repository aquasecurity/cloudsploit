var async = require('async');
var helpers = require('../../helpers');

var badCiphers = [
	'Protocol-SSLv2',
	'Protocol-SSLv3',
	'DHE-RSA-AES128-SHA',
	'DHE-DSS-AES128-SHA',
	'CAMELLIA128-SHA',
	'EDH-RSA-DES-CBC3-SHA',
	'ECDHE-RSA-RC4-SHA',
	'RC4-SHA',
	'ECDHE-ECDSA-RC4-SHA',
	'DHE-DSS-AES256-GCM-SHA384',
	'DHE-RSA-AES256-GCM-SHA384',
	'DHE-RSA-AES256-SHA256',
	'DHE-DSS-AES256-SHA256',
	'DHE-RSA-AES256-SHA',
	'DHE-DSS-AES256-SHA',
	'DHE-RSA-CAMELLIA256-SHA',
	'DHE-DSS-CAMELLIA256-SHA',
	'CAMELLIA256-SHA',
	'EDH-DSS-DES-CBC3-SHA',
	'DHE-DSS-AES128-GCM-SHA256',
	'DHE-RSA-AES128-GCM-SHA256',
	'DHE-RSA-AES128-SHA256',
	'DHE-DSS-AES128-SHA256',
	'DHE-RSA-CAMELLIA128-SHA',
	'DHE-DSS-CAMELLIA128-SHA',
	'ADH-AES128-GCM-SHA256',
	'ADH-AES128-SHA',
	'ADH-AES128-SHA256',
	'ADH-AES256-GCM-SHA384',
	'ADH-AES256-SHA',
	'ADH-AES256-SHA256',
	'ADH-CAMELLIA128-SHA',
	'ADH-CAMELLIA256-SHA',
	'ADH-DES-CBC3-SHA',
	'ADH-DES-CBC-SHA',
	'ADH-RC4-MD5',
	'ADH-SEED-SHA',
	'DES-CBC-SHA',
	'DHE-DSS-SEED-SHA',
	'DHE-RSA-SEED-SHA',
	'EDH-DSS-DES-CBC-SHA',
	'EDH-RSA-DES-CBC-SHA',
	'IDEA-CBC-SHA',
	'RC4-MD5',
	'SEED-SHA',
	'DES-CBC3-MD5',
	'DES-CBC-MD5',
	'RC2-CBC-MD5',
	'PSK-AES256-CBC-SHA',
	'PSK-3DES-EDE-CBC-SHA',
	'KRB5-DES-CBC3-SHA',
	'KRB5-DES-CBC3-MD5',
	'PSK-AES128-CBC-SHA',
	'PSK-RC4-SHA',
	'KRB5-RC4-SHA',
	'KRB5-RC4-MD5',
	'KRB5-DES-CBC-SHA',
	'KRB5-DES-CBC-MD5',
	'EXP-EDH-RSA-DES-CBC-SHA',
	'EXP-EDH-DSS-DES-CBC-SHA',
	'EXP-ADH-DES-CBC-SHA',
	'EXP-DES-CBC-SHA',
	'EXP-RC2-CBC-MD5',
	'EXP-KRB5-RC2-CBC-SHA',
	'EXP-KRB5-DES-CBC-SHA',
	'EXP-KRB5-RC2-CBC-MD5',
	'EXP-KRB5-DES-CBC-MD5',
	'EXP-ADH-RC4-MD5',
	'EXP-RC4-MD5',
	'EXP-KRB5-RC4-SHA',
	'EXP-KRB5-RC4-MD5'
];

module.exports = {
	title: 'Insecure Ciphers',
	category: 'ELB',
	description: 'Detect use of insecure ciphers on ELBs',
	more_info: 'Various security vulnerabilities have rendered several ciphers insecure. Only the recommended ciphers should be used.',
	link: 'http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-options.html',
	recommended_action: 'Update your ELBs to use the recommended cipher suites',
	apis: ['ELB:describeLoadBalancers', 'ELB:describeLoadBalancerPolicies'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.elb, function(region, rcb){
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
				if (!lb.DNSName) return cb();

				var describeLoadBalancerPolicies = helpers.addSource(cache, source,
					['elb', 'describeLoadBalancerPolicies', region, lb.DNSName]);

				// If the LB wasn't using HTTPS, just skip it
				if (!describeLoadBalancerPolicies ||
					(!describeLoadBalancerPolicies.err && !describeLoadBalancerPolicies.data)) return cb();

				if (describeLoadBalancerPolicies.err || !describeLoadBalancerPolicies.data) {
					helpers.addResult(results, 3,
						'Unable to query load balancer policies for ELB: ' + lb.LoadBalancerName,
						region, lb.DNSName);

					return cb();
				}

				for (i in describeLoadBalancerPolicies.data.PolicyDescriptions) {
					var policyDesc = describeLoadBalancerPolicies.data.PolicyDescriptions[i];

					var elbBad = [];

					for (j in policyDesc.PolicyAttributeDescriptions) {
						var policyAttrDesc = policyDesc.PolicyAttributeDescriptions[j];

						if (policyAttrDesc.AttributeValue === 'true' &&
							badCiphers.indexOf(policyAttrDesc.AttributeName) > -1) {
							elbBad.push(policyAttrDesc.AttributeName);
						}
					}

					if (elbBad.length) {
						helpers.addResult(results, 1,
							'ELB: ' + lb.LoadBalancerName + ' uses insecure protocols or ciphers: ' + elbBad.join(', '),
							region, lb.DNSName);
					} else {
						helpers.addResult(results, 0,
							'ELB: ' + lb.LoadBalancerName + ' uses secure protocols and ciphers',
							region, lb.DNSName);
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