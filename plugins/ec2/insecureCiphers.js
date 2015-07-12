var AWS = require('aws-sdk');
var async = require('async');

function getPluginInfo() {
	return {
		title: 'Insecure Ciphers',
		query: 'insecureCiphers',
		category: 'EC2',
		description: 'Detect use of insecure ciphers on ELBs',
		tests: {
			insecureCiphers: {
				title: 'Insecure Ciphers',
				description: 'Detect use of insecure ciphers on ELBs',
				more_info: 'Various security vulnerabilities have rendered several ciphers insecure. Only the reccommended ciphers should be used.',
				link: 'http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-options.html',
				recommended_action: 'Update your ELBs to use the reccommended cipher suites',
				results: []
			}
		}
	}
};

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
	title: getPluginInfo().title,
	query: getPluginInfo().query,
	category: getPluginInfo().category,
	description: getPluginInfo().description,
	more_info: getPluginInfo().more_info,
	link: getPluginInfo().link,
	tests: getPluginInfo().tests,

	run: function(AWSConfig, callback) {
		var elb = new AWS.ELB(AWSConfig);
		var pluginInfo = getPluginInfo();

		elb.describeLoadBalancers({}, function(err, data){
			if (err || !data || !data.LoadBalancerDescriptions) {
				pluginInfo.tests.insecureCiphers.results.push({
					status: 3,
					message: 'Unable to query for load balancers'
				});

				return callback(null, pluginInfo);
			}

			// Gather list of policies from load balancers
			var policies = [];

			for (i in data.LoadBalancerDescriptions) {
				for (j in data.LoadBalancerDescriptions[i].ListenerDescriptions) {
					if (data.LoadBalancerDescriptions[i].ListenerDescriptions[j].Listener.Protocol === 'HTTPS') {
						var elbPolicies = [];
						for (k in data.LoadBalancerDescriptions[i].ListenerDescriptions[j].PolicyNames) {
							elbPolicies.push(data.LoadBalancerDescriptions[i].ListenerDescriptions[j].PolicyNames[k]);
						}
						if (elbPolicies.length) {
							var elbObj = {
								LoadBalancerName: data.LoadBalancerDescriptions[i].LoadBalancerName,
								PolicyNames: elbPolicies
							};
							policies.push(elbObj);
						}
					}
				}
			}

			if (!policies.length) {
				pluginInfo.tests.insecureCiphers.results.push({
					status: 0,
					message: 'No load balancers are using HTTPS'
				});

				return callback(null, pluginInfo);
			}

			if (policies.length > 30) {
				pluginInfo.tests.insecureCiphers.results.push({
					status: 3,
					message: 'More than 30 load balancers found. Only the first 30 are checked.'
				});

				policies = policies.slice(0,30);
			}

			async.eachLimit(policies, 4, function(policy, cb){
				elb.describeLoadBalancerPolicies(policy, function(err, data){
					if (err || !data || !data.PolicyDescriptions) {
						pluginInfo.tests.insecureCiphers.results.push({
							status: 3,
							message: 'Unable to query load balancer policies for ELB: ' + policy.LoadBalancerName
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
							pluginInfo.tests.insecureCiphers.results.push({
								status: 1,
								message: 'ELB: ' + policy.LoadBalancerName + ' uses insecure protocols or ciphers: ' + elbBad.join(', ')
							});
						} else {
							pluginInfo.tests.insecureCiphers.results.push({
								status: 0,
								message: 'ELB: ' + policy.LoadBalancerName + ' uses secure protocols and ciphers'
							});
						}
					}
					cb();
				});
			}, function(){
				callback(null, pluginInfo);
			});
		});
	}
};