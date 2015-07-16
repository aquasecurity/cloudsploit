var AWS = require('aws-sdk');
var async = require('async');

function getPluginInfo() {
	return {
		title: 'Security Groups',
		query: 'securityGroups',
		category: 'EC2',
		description: 'Determine if sensitive ports are open to all source addresses',
		tests: {
			excessiveSecurityGroups: {
				title: 'Excessive Securtiy Groups',
				description: 'Determine if there are an excessive number of security groups in the account',
				more_info: 'Keeping the number of security groups to a minimum helps reduce the attack surface of an account. Rather than creating new groups with the same rules for each project, common rules should be grouped under the same security groups. For example, instead of adding port 22 from a known IP to every group, create a single "SSH" security group which can be used on multiple instances.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Limit the number of security groups to prevent accidental authorizations',
				results: []
			},
			openFTP: {
				title: 'Open FTP',
				description: 'Determine if TCP port 20 or 21 for FTP is open to the public',
				more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as FTP should be restricted to known IP addresses.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Restrict TCP ports 20 and 21 to known IP addresses',
				results: []
			},
			openSSH: {
				title: 'Open SSH',
				description: 'Determine if TCP port 22 for SSH is open to the public',
				more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as SSH should be restricted to known IP addresses.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Restrict TCP port 22 to known IP addresses',
				results: []
			},
			openTelnet: {
				title: 'Open Telnet',
				description: 'Determine if TCP port 23 for Telnet is open to the public',
				more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Telnet should be restricted to known IP addresses.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Restrict TCP port 23 to known IP addresses',
				results: []
			},
			openSMTP: {
				title: 'Open SMTP',
				description: 'Determine if TCP port 25 for SMTP is open to the public',
				more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as SMTP should be restricted to known IP addresses.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Restrict TCP port 25 to known IP addresses',
				results: []
			},
			openDNS: {
				title: 'Open DNS',
				description: 'Determine if TCP or UDP port 53 for DNS is open to the public',
				more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as DNS should be restricted to known IP addresses.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Restrict TCP and UDP port 53 to known IP addresses',
				results: []
			},
			openRPC: {
				title: 'Open RPC',
				description: 'Determine if TCP port 135 for RCP is open to the public',
				more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as RCP should be restricted to known IP addresses.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Restrict TCP port 135 to known IP addresses',
				results: []
			},
			openNetBIOS: {
				title: 'Open NetBIOS',
				description: 'Determine if UDP port 137 or 138 for NetBIOS is open to the public',
				more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as NetBIOS should be restricted to known IP addresses.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Restrict UDP ports 137 and 138 to known IP addresses',
				results: []
			},
			openSMBoTCP: {
				title: 'Open SMBoTCP',
				description: 'Determine if TCP port 445 for Windows SMB over TCP is open to the public',
				more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as SMB should be restricted to known IP addresses.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Restrict TCP port 445 to known IP addresses',
				results: []
			},
			openCIFS: {
				title: 'Open CIFS',
				description: 'Determine if UDP port 445 for CIFS is open to the public',
				more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as CIFS should be restricted to known IP addresses.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Restrict UDP port 445 to known IP addresses',
				results: []
			},
			openSQLServer: {
				title: 'Open SQL Server',
				description: 'Determine if TCP port 1433 or UDP port 1434 for SQL Server is open to the public',
				more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as SQL server should be restricted to known IP addresses.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Restrict TCP port 1433 and UDP port 1434 to known IP addresses',
				results: []
			},
			openRDP: {
				title: 'Open RDP',
				description: 'Determine if TCP port 3389 for RDP is open to the public',
				more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as RDP should be restricted to known IP addresses.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Restrict TCP port 3389 to known IP addresses',
				results: []
			},
			openMySQL: {
				title: 'Open MySQL',
				description: 'Determine if TCP port 4333 or 3306 for MySQL is open to the public',
				more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as MySQL should be restricted to known IP addresses.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Restrict TCP ports 4333 and 3306 to known IP addresses',
				results: []
			},
			openPostgreSQL: {
				title: 'Open PostgreSQL',
				description: 'Determine if TCP port 5432 for PostgreSQL is open to the public',
				more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as PostgreSQL should be restricted to known IP addresses.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Restrict TCP port 5432 to known IP addresses',
				results: []
			},
			openVNCClient: {
				title: 'Open VNC Client',
				description: 'Determine if TCP port 5500 for VNC Client is open to the public',
				more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as VNC Client should be restricted to known IP addresses.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Restrict TCP port 5500 to known IP addresses',
				results: []
			},
			openVNCServer: {
				title: 'Open VNC Server',
				description: 'Determine if TCP port 5900 for VNC Server is open to the public',
				more_info: 'While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as VNC Server should be restricted to known IP addresses.',
				link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
				recommended_action: 'Restrict TCP port 5900 to known IP addresses',
				results: []
			}
		}
	};
}

module.exports = {
	title: getPluginInfo().title,
	query: getPluginInfo().query,
	category: getPluginInfo().category,
	description: getPluginInfo().description,
	more_info: getPluginInfo().more_info,
	link: getPluginInfo().link,
	tests: getPluginInfo().tests,

	run: function(AWSConfig, callback) {
		var ec2 = new AWS.EC2(AWSConfig);
		var pluginInfo = getPluginInfo();

		// Get the account attributes
		ec2.describeSecurityGroups({}, function(err, data){
			if (err) {
				var statusObj = {
					status: 3,
					message: 'Unable to query for security groups'
				};

				// Add unknown result to all tests
				for (i in pluginInfo.tests) {
					pluginInfo.tests[i].results.push(statusObj);
				}

				return callback(null, pluginInfo);
			}

			// Loop through response to assign custom limits
			if (data && data.SecurityGroups && data.SecurityGroups.length) {
				if (data.SecurityGroups.length > 40) {
					pluginInfo.tests.excessiveSecurityGroups.results.push({
						status: 2,
						message: 'Excessive number of security groups: ' + data.SecurityGroups.length + ' groups present'
					});
				} else if (data.SecurityGroups.length > 30) {
					pluginInfo.tests.excessiveSecurityGroups.results.push({
						status: 1,
						message: 'Large number of security groups: ' + data.SecurityGroups.length + ' groups present'
					});
				} else {
					pluginInfo.tests.excessiveSecurityGroups.results.push({
						status: 0,
						message: 'Acceptable number of security groups: ' + data.SecurityGroups.length + ' groups present'
					});
				}

				for (i in data.SecurityGroups) {
					for (j in data.SecurityGroups[i].IpPermissions) {
						var permission = data.SecurityGroups[i].IpPermissions[j];

						for (k in permission.IpRanges) {
							var range = permission.IpRanges[k];

							if (range.CidrIp === '0.0.0.0/0') {

								// All tests
								if (permission.IpProtocol === 'tcp' && ( (permission.FromPort <= 20 && permission.ToPort >= 20) || (permission.FromPort <= 21 && permission.ToPort >= 21) ) ) {
									pluginInfo.tests.openFTP.results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has FTP TCP port 20 and/or 21 open to 0.0.0.0/0'
									});
								}

								if (permission.IpProtocol === 'tcp' && permission.FromPort <= 22 && permission.ToPort >= 22) {
									pluginInfo.tests.openSSH.results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has SSH TCP port 22 open to 0.0.0.0/0'
									});
								}

								if (permission.IpProtocol === 'tcp' && permission.FromPort <= 23 && permission.ToPort >= 23) {
									pluginInfo.tests.openTelnet.results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has Telnet TCP port 23 open to 0.0.0.0/0'
									});
								}

								if (permission.IpProtocol === 'tcp' && permission.FromPort <= 25 && permission.ToPort >= 25) {
									pluginInfo.tests.openSMTP.results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has SMTP TCP port 25 open to 0.0.0.0/0'
									});
								}

								if ( (permission.IpProtocol === 'tcp' || permission.IpProtocol === 'udp') && permission.FromPort <= 53 && permission.ToPort >= 53) {
									pluginInfo.tests.openDNS.results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has DNS TCP and/or UDP port 53 open to 0.0.0.0/0'
									});
								}

								if (permission.IpProtocol === 'tcp' && permission.FromPort <= 135 && permission.ToPort >= 135) {
									pluginInfo.tests.openRPC.results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has RPC TCP port 135 open to 0.0.0.0/0'
									});
								}

								if (permission.IpProtocol === 'tcp' && ( (permission.FromPort <= 137 && permission.ToPort >= 137) || (permission.FromPort <= 138 && permission.ToPort >= 138) ) ) {
									pluginInfo.tests.openNetBIOS.results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has NetBIOS TCP port 137 and/or 138 open to 0.0.0.0/0'
									});
								}

								if (permission.IpProtocol === 'tcp' && permission.FromPort <= 445 && permission.ToPort >= 445) {
									pluginInfo.tests.openSMBoTCP.results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has SMBoTCP TCP port 445 open to 0.0.0.0/0'
									});
								}

								if (permission.IpProtocol === 'udp' && permission.FromPort <= 445 && permission.ToPort >= 445) {
									pluginInfo.tests.openCIFS.results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has CIFS TCP port 445 open to 0.0.0.0/0'
									});
								}

								if ( (permission.IpProtocol === 'tcp' && permission.FromPort <= 1433 && permission.ToPort >= 1433) || (permission.IpProtocol === 'udp' && permission.FromPort <= 1434 && permission.ToPort >= 1434) ) {
									pluginInfo.tests.openSQLServer.results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has SQL Server TCP port 1433 or UDP port 1434 open to 0.0.0.0/0'
									});
								}

								if (permission.IpProtocol === 'tcp' && permission.FromPort <= 3389 && permission.ToPort >= 3389) {
									pluginInfo.tests.openRDP.results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has RDP TCP port 3389 open to 0.0.0.0/0'
									});
								}

								if (permission.IpProtocol === 'tcp' && ( (permission.FromPort <= 3306 && permission.ToPort >= 3306) || (permission.FromPort <= 4333 && permission.ToPort >= 4333) ) ) {
									pluginInfo.tests.openMySQL.results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has MySQL TCP port 3306 and/or 4333 open to 0.0.0.0/0'
									});
								}

								if (permission.IpProtocol === 'tcp' && permission.FromPort <= 5432 && permission.ToPort >= 5432) {
									pluginInfo.tests.openPostgreSQL.results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has PostgreSQL TCP port 5432 open to 0.0.0.0/0'
									});
								}

								if (permission.IpProtocol === 'tcp' && permission.FromPort <= 5500 && permission.ToPort >= 5500) {
									pluginInfo.tests.openVNCClient.results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has VNC Client TCP port 5500 open to 0.0.0.0/0'
									});
								}

								if (permission.IpProtocol === 'tcp' && permission.FromPort <= 5900 && permission.ToPort >= 5900) {
									pluginInfo.tests.openVNCServer.results.push({
										status: 2,
										message: 'Security group: ' + data.SecurityGroups[i].GroupId + ' (' + data.SecurityGroups[i].GroupName + ') has VNC Server TCP port 5900 open to 0.0.0.0/0'
									});
								}
							}
						}
					}
				}
				
				// Afterwards, if a test doesn't have any negative results, add an okay result
				for (i in pluginInfo.tests) {
					if (!pluginInfo.tests[i].results.length) {
						pluginInfo.tests[i].results.push({
							status: 0,
							message: 'No public open ports found'
						});
					}
				}

				return callback(null, pluginInfo);
			} else {
				var statusObj = {
					status: 3,
					message: 'Unable to query for security groups'
				};

				// Add unknown result to all tests
				for (i in pluginInfo.tests) {
					pluginInfo.tests[i].results.push(statusObj);
				}

				return callback(null, pluginInfo);
			}
		});
	}
};