var AWS = require('aws-sdk');

function getPluginInfo() {
	return {
		title: 'Domain Security',
		query: 'domainSecurity',
		category: 'Route53',
		description: 'Ensures domains are properly configured in Route53',
		tests: {
			domainAutoRenew: {
				title: 'Domain Auto Renew',
				description: 'Ensures domains are set to auto renew through Route53',
				more_info: 'Domains purchased through Route53 should be set to auto renew. Domains that are not renewed can quickly be acquired by a third-party and cause loss of access for customers.',
				link: 'http://docs.aws.amazon.com/Route53/latest/APIReference/api-enable-domain-auto-renew.html',
				recommended_action: 'Enable auto renew for the domain',
				results: []
			},
			domainTransferLock: {
				title: 'Domain Transfer Lock',
				description: 'Ensures domains have the transfer lock set',
				more_info: 'To avoid having a domain maliciously transferred to a third-party, all domains should enable the transfer lock unless actively being tranferred.',
				link: 'http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-transfer-from-route-53.html',
				recommended_action: 'Enable the transfer lock for the domain',
				results: []
			},
			domainExpiry: {
				title: 'Domain Expiry',
				description: 'Ensures domains are not expiring too soon',
				more_info: 'Expired domains can be lost and reregistered by a third-party.',
				link: 'http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/registrar.html',
				recommended_action: 'Reregister the expiring domain',
				results: []
			}
		}
	}
};

module.exports = {
	title: getPluginInfo().title,
	query: getPluginInfo().query,
	category: getPluginInfo().category,
	description: getPluginInfo().description,
	more_info: getPluginInfo().more_info,
	link: getPluginInfo().link,
	tests: getPluginInfo().tests,

	run: function(AWSConfig, callback) {
		var pluginInfo = getPluginInfo();
		var route53domains = new AWS.Route53Domains(AWSConfig);

		route53domains.listDomains({MaxItems:100}, function(err, data){
			if (err || !data) {
				var statusObj = {
					status: 3,
					message: 'Unable to query for domains',
					region: 'global'
				};

				pluginInfo.tests.domainAutoRenew.results.push(statusObj);
				pluginInfo.tests.domainTransferLock.results.push(statusObj);
				pluginInfo.tests.domainExpiry.results.push(statusObj);

				return callback(null, pluginInfo);
			}

			if (!data.Domains || !data.Domains.length) {
				var statusObj = {
					status: 0,
					message: 'No domains registered through Route53',
					region: 'global'
				};

				pluginInfo.tests.domainAutoRenew.results.push(statusObj);
				pluginInfo.tests.domainTransferLock.results.push(statusObj);
				pluginInfo.tests.domainExpiry.results.push(statusObj);

				return callback(null, pluginInfo);
			}

			var now = new Date();

			for (i in data.Domains) {

				// Auto renewals

				if (data.Domains[i].AutoRenew) {
					pluginInfo.tests.domainAutoRenew.results.push({
						status: 0,
						message: 'Domain: ' + data.Domains[i].DomainName + ' has auto renew enabled',
						resource: data.Domains[i].DomainName,
						region: 'global'
					});
				} else {
					pluginInfo.tests.domainAutoRenew.results.push({
						status: 1,
						message: 'Domain: ' + data.Domains[i].DomainName + ' does not have auto renew enabled',
						resource: data.Domains[i].DomainName,
						region: 'global'
					});
				}

				// Transfer lock

				if (data.Domains[i].TransferLock) {
					pluginInfo.tests.domainTransferLock.results.push({
						status: 0,
						message: 'Domain: ' + data.Domains[i].DomainName + ' has the transfer lock enabled',
						resource: data.Domains[i].DomainName,
						region: 'global'
					});
				} else {
					pluginInfo.tests.domainTransferLock.results.push({
						status: 2,
						message: 'Domain: ' + data.Domains[i].DomainName + ' does not have the transfer lock enabled',
						resource: data.Domains[i].DomainName,
						region: 'global'
					});
				}

				// Domain expiry
				if (data.Domains[i].Expiry) {
					var then = new Date(data.Domains[i].Expiry);
					var difference = Math.floor((then - now) / 1000 / 60 / 60 / 24);	// number of days difference

					if (difference > 45) {
						pluginInfo.tests.domainExpiry.results.push({
							status: 0,
							message: 'Domain: ' + data.Domains[i].DomainName + ' expires in ' + Math.abs(difference) + ' days',
							region: 'global',
							resource: data.Domains[i].DomainName
						});
					} else if (difference > 30) {
						pluginInfo.tests.domainExpiry.results.push({
							status: 1,
							message: 'Domain: ' + data.Domains[i].DomainName + ' expires in ' + Math.abs(difference) + ' days',
							region: 'global',
							resource: data.Domains[i].DomainName
						});
					} else if (difference > 0) {
						pluginInfo.tests.domainExpiry.results.push({
							status: 2,
							message: 'Domain: ' + data.Domains[i].DomainName + ' expires in ' + Math.abs(difference) + ' days',
							region: 'global',
							resource: data.Domains[i].DomainName
						});
					} else {
						pluginInfo.tests.domainExpiry.results.push({
							status: 2,
							message: 'Domain: ' + data.Domains[i].DomainName + ' expired ' + Math.abs(difference) + ' days ago',
							region: 'global',
							resource: data.Domains[i].DomainName
						});
					}
				} else {
					pluginInfo.tests.domainExpiry.results.push({
						status: 3,
						message: 'Expiration for domain: ' + data.Domains[i].DomainName + ' could not be determined',
						resource: data.Domains[i].DomainName,
						region: 'global'
					});
				}
			}

			callback(null, pluginInfo);
		});
	}
};
