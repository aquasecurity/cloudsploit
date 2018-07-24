var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Security Group Unused',
	category: 'EC2',
	description: 'Ensures that security groups that are present in the account are actively in use.',
	more_info: 'EC2 security groups should be kept to a minimum to avoid unnecessary management overhead. If groups are no longer used by resources, they should be deleted.',
	link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html#vpc-security-groups',
	apis: [
		'EC2:describeInstances',
		'EC2:describeSecurityGroups',
		'AppStream:describeFleets',
		'EFS:describeMountTargets',
		'EFS:describeMountTargetSecurityGroups',
		'DAX:describeClusters',
		'EKS:describeCluster',
		'ELB:describeLoadBalancers',
		'ELBv2:describeLoadBalancers',
		'ES:describeElasticsearchDomain',
		'MediaLive:listInputSecurityGroups',
		'Neptune:describeDBClusters',
		'RDS:describeDBSecurityGroups',
		'Redshift:describeClusterSecurityGroups',
		'SageMaker:describeNotebookInstance',
		'WorkSpaces:describeWorkspaceDirectories'
	],
	run: function(cache, settings, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.ec2, function(region, rcb){
			
			var describeInstances = helpers.addSource(cache, source, ['ec2', 'describeInstances', region]);
			
			if (!describeInstances) return rcb();

			if (describeInstances.err || !describeInstances.data) {
				helpers.addResult(results, 3,
					'Unable to query for EC2 instances: ' + helpers.addError(describeInstances), region);
				return rcb();
			}

			if (!describeInstances.data.length) {
				helpers.addResult(results, 0, 'No EC2 instances found', region);
				return rcb();
			}

			var ownerId = describeInstances.data[0].OwnerId || '';
			var inuseSecurityGroups	= [];
			
			// For EC2
			for (i in describeInstances.data) {
				for (j in describeInstances.data[i].Instances) {
					for (k in describeInstances.data[i].Instances[j].SecurityGroups) {
						if(inuseSecurityGroups.indexOf(describeInstances.data[i].Instances[j].SecurityGroups[k].GroupId) == -1) {
							inuseSecurityGroups.push({
								serviceName: 'ec2',
								secGroupId: describeInstances.data[i].Instances[j].SecurityGroups[k].GroupId,
								arn: 'arn:aws:ec2:'+region+':'+ownerId+':security-group/'+describeInstances.data[i].Instances[j].SecurityGroups[k].GroupId
							});
						}
					}
				}
			}

			var describeSecurityGroups = helpers.addSource(cache, source, ['ec2', 'describeSecurityGroups', region]);

			if (!describeSecurityGroups) return rcb();

			if (describeSecurityGroups.err || !describeSecurityGroups.data) {
				helpers.addResult(results, 3,
					'Unable to query for security groups: ' + helpers.addError(describeSecurityGroups), region);
				return rcb();
			}

			if (!describeSecurityGroups.data.length) {
				helpers.addResult(results, 0, 'No security groups found', region);
				return rcb();
			}

			var securityGroups	= describeSecurityGroups.data;

			// For AppStream
			var describeFleets = helpers.addSource(cache, source, ['appstream', 'describeFleets', region]);
			if (describeFleets) {
				if (describeFleets.err || !describeFleets.data) {
					helpers.addResult(results, 3, 'Unable to query for AppStream: ' + helpers.addError(describeFleets), region);
				} else {
					for (i in describeFleets.data) {
						for (j in describeFleets.data[i].VpcConfig.SecurityGroupIds) {
							if(inuseSecurityGroups.indexOf(describeFleets.data[i].VpcConfig.SecurityGroupIds[j]) == -1) {
								inuseSecurityGroups.push({
									serviceName: 'appstream',
									secGroupId: describeFleets.data[i].VpcConfig.SecurityGroupIds[j],
									arn: 'arn:aws:appstream:'+region+':'+ownerId+':security-group/'+describeFleets.data[i].VpcConfig.SecurityGroupIds[j]
								});
							}
						}
					}
				}
			}

			// For EFS
			var describeMountTargets = helpers.addSource(cache, source, ['efs', 'describeMountTargets', region]);
			var describeMountTargetsData = [];

			if (describeMountTargets) {
				if (describeMountTargets.err || !describeMountTargets.data) {
					helpers.addResult(results, 3, 'Unable to query for EFS: ' + helpers.addError(describeMountTargets), region);
				} else {
					describeMountTargetsData = describeMountTargets.data;
				}
			}

			// For DAX
			var describeClusters = helpers.addSource(cache, source, ['dax', 'describeClusters', region]);
			if (describeClusters) {
				if (describeClusters.err || !describeClusters.data) {
					helpers.addResult(results, 3, 'Unable to query for DAX: ' + helpers.addError(describeClusters), region);
				} else {
					for (i in describeClusters.data) {
						for (j in describeClusters.data[i].SecurityGroups) {
							if(inuseSecurityGroups.indexOf(describeClusters.data[i].SecurityGroups[j].SecurityGroupIdentifier) == -1) {
								inuseSecurityGroups.push({
									serviceName: 'dax',
									secGroupId: describeClusters.data[i].SecurityGroups[j].SecurityGroupIdentifier,
									arn: 'arn:aws:dax:'+region+':'+ownerId+':security-group/'+describeClusters.data[i].SecurityGroups[j].SecurityGroupIdentifier
								});
							}
						}
					}
				}
			}

			// For EKS
			var describeCluster = helpers.addSource(cache, source, ['eks', 'describeCluster', region]);
			if (describeCluster) {
				if (describeCluster.err || !describeCluster.data) {
					helpers.addResult(results, 3, 'Unable to query for EKS: ' + helpers.addError(describeCluster), region);
				} else {
					for (i in describeCluster.data) {
						for (j in describeCluster.data[i].resourcesVpcConfig.securityGroupIds) {
							if(inuseSecurityGroups.indexOf(describeCluster.data[i].resourcesVpcConfig.securityGroupIds[j]) == -1) {
								inuseSecurityGroups.push({
									serviceName: 'eks',
									secGroupId: describeCluster.data[i].resourcesVpcConfig.securityGroupIds[j],
									arn: 'arn:aws:eks:'+region+':'+ownerId+':security-group/'+describeCluster.data[i].resourcesVpcConfig.securityGroupIds[j]
								});
							}
						}
					}
				}
			}

			// For ELB
			var describeLoadBalancers = helpers.addSource(cache, source, ['elb', 'describeLoadBalancers', region]);
			if (describeLoadBalancers) {
				if (describeLoadBalancers.err || !describeLoadBalancers.data) {
					helpers.addResult(results, 3, 'Unable to query for ELB: ' + helpers.addError(describeLoadBalancers), region);
				} else {
					for (i in describeLoadBalancers.data) {
						for (j in describeLoadBalancers.data[i].SecurityGroups) {
							if(inuseSecurityGroups.indexOf(describeLoadBalancers.data[i].SecurityGroups[j]) == -1) {
								inuseSecurityGroups.push({
									serviceName: 'elb',
									secGroupId: describeLoadBalancers.data[i].SecurityGroups[j],
									arn: 'arn:aws:elb:'+region+':'+ownerId+':security-group/'+describeLoadBalancers.data[i].SecurityGroups[j]
								});
							}
						}
					}
				}
			}

			// For ELBv2
			var describeLoadBalancers = helpers.addSource(cache, source, ['elbv2', 'describeLoadBalancers', region]);
			if (describeLoadBalancers) {
				if (describeLoadBalancers.err || !describeLoadBalancers.data) {
					helpers.addResult(results, 3, 'Unable to query for ELBv2: ' + helpers.addError(describeLoadBalancers), region);
				} else {
					for (i in describeLoadBalancers.data) {
						for (j in describeLoadBalancers.data[i].SecurityGroups) {
							if(inuseSecurityGroups.indexOf(describeLoadBalancers.data[i].SecurityGroups[j]) == -1) {
								inuseSecurityGroups.push({
									serviceName: 'elbv2',
									secGroupId: describeLoadBalancers.data[i].SecurityGroups[j],
									arn: 'arn:aws:elbv2:'+region+':'+ownerId+':security-group/'+describeLoadBalancers.data[i].SecurityGroups[j]
								});
							}
						}
					}
				}
			}

			// For ES
			var describeElasticsearchDomain = helpers.addSource(cache, source, ['es', 'describeElasticsearchDomain', region]);
			if (describeElasticsearchDomain) {
				if (describeElasticsearchDomain.err || !describeElasticsearchDomain.data) {
					helpers.addResult(results, 3, 'Unable to query for ES: ' + helpers.addError(describeElasticsearchDomain), region);
				} else {
					for (i in describeElasticsearchDomain.data) {
						for (j in describeElasticsearchDomain.data[i].VPCOptions.SecurityGroupIds) {
							if(inuseSecurityGroups.indexOf(describeElasticsearchDomain.data[i].VPCOptions.SecurityGroupIds[j]) == -1) {
								inuseSecurityGroups.push({
									serviceName: 'es',
									secGroupId: describeElasticsearchDomain.data[i].VPCOptions.SecurityGroupIds[j],
									arn: 'arn:aws:es:'+region+':'+ownerId+':security-group/'+describeElasticsearchDomain.data[i].VPCOptions.SecurityGroupIds[j]
								});
							}
						}
					}
				}
			}

			// For MediaLive
			var listInputSecurityGroups = helpers.addSource(cache, source, ['medialive', 'listInputSecurityGroups', region]);

			if (listInputSecurityGroups) {
				if (listInputSecurityGroups.err || !listInputSecurityGroups.data) {
					helpers.addResult(results, 3, 'Unable to query for MediaLive: ' + helpers.addError(listInputSecurityGroups), region);
				} else {
					for (i in listInputSecurityGroups.data){
						if(inuseSecurityGroups.indexOf(listInputSecurityGroups.data[i].Id) == -1) {
							inuseSecurityGroups.push({
								serviceName: 'medialive',
								secGroupId: listInputSecurityGroups.data[i].Id,
								arn: 'arn:aws:medialive:'+region+':'+ownerId+':security-group/'+listInputSecurityGroups.data[i].Id
							});
						}
					}
				}
			}

			// For Neptune
			var describeDBClusters = helpers.addSource(cache, source, ['neptune', 'describeDBClusters', region]);

			if (describeDBClusters) {
				if (describeDBClusters.err || !describeDBClusters.data) {
					helpers.addResult(results, 3, 'Unable to query for Neptune: ' + helpers.addError(describeDBClusters), region);
				} else {
					for (i in describeDBClusters.data) {
						for (j in describeDBClusters.data[i].VpcSecurityGroups) {
							if(inuseSecurityGroups.indexOf(describeDBClusters.data[i].VpcSecurityGroups[j].VpcSecurityGroupId) == -1) {
								inuseSecurityGroups.push({
									serviceName: 'neptune',
									secGroupId: describeDBClusters.data[i].VpcSecurityGroups[j].VpcSecurityGroupId,
									arn: 'arn:aws:neptune:'+region+':'+ownerId+':security-group/'+describeDBClusters.data[i].VpcSecurityGroups[j].VpcSecurityGroupId
								});
							}
						}
					}
				}
			}

			// For RDS
			var describeDBSecurityGroups = helpers.addSource(cache, source, ['rds', 'describeDBSecurityGroups', region]);

			if (describeDBSecurityGroups) {
				if (describeDBSecurityGroups.err || !describeDBSecurityGroups.data) {
					helpers.addResult(results, 3, 'Unable to query for RDS: ' + helpers.addError(describeDBSecurityGroups), region);
				} else {
					for (i in describeDBSecurityGroups.data) {
						for (j in describeDBSecurityGroups.data[i].EC2SecurityGroups) {
							if(inuseSecurityGroups.indexOf(describeDBSecurityGroups.data[i].EC2SecurityGroups[j].EC2SecurityGroupId) == -1) {
								inuseSecurityGroups.push({
									serviceName: 'rds',
									secGroupId: describeDBSecurityGroups.data[i].EC2SecurityGroups[j].EC2SecurityGroupId,
									arn: 'arn:aws:rds:'+region+':'+ownerId+':security-group/'+describeDBSecurityGroups.data[i].EC2SecurityGroups[j].EC2SecurityGroupId
								});
							}
						}
					}
				}
			}

			// For Redshift
			var describeClusterSecurityGroups = helpers.addSource(cache, source, ['redshift', 'describeClusterSecurityGroups', region]);

			if (describeClusterSecurityGroups) {
				if (describeClusterSecurityGroups.err || !describeClusterSecurityGroups.data) {
					helpers.addResult(results, 3, 'Unable to query for Redshift cluster security groups: ' + helpers.addError(describeClusterSecurityGroups), region);
				} else {
					for (i in describeClusterSecurityGroups.data){
						for (j in describeClusterSecurityGroups.data[i].EC2SecurityGroups){
							if(inuseSecurityGroups.indexOf(describeClusterSecurityGroups.data[i].EC2SecurityGroups[j].EC2SecurityGroupName) == -1) {
								inuseSecurityGroups.push({
									serviceName: 'redshift',
									secGroupId: describeClusterSecurityGroups.data[i].EC2SecurityGroups[j].EC2SecurityGroupName,
									arn: 'arn:aws:redshift:'+region+':'+ownerId+':security-group/'+describeClusterSecurityGroups.data[i].EC2SecurityGroups[j].EC2SecurityGroupName
								});
							}
						}
					}
				}
			}

			// For SageMaker
			var describeNotebookInstance = helpers.addSource(cache, source, ['sagemaker', 'describeNotebookInstance', region]);

			if (describeNotebookInstance) {
				if (describeNotebookInstance.err || !describeNotebookInstance.data) {
					helpers.addResult(results, 3, 'Unable to query for sagemaker: ' + helpers.addError(describeNotebookInstance), region);
				} else {
					for (i in describeNotebookInstance.data){
						if(inuseSecurityGroups.indexOf(describeNotebookInstance.data[i]) == -1) {
							inuseSecurityGroups.push({
								serviceName: 'sagemaker',
								secGroupId: describeNotebookInstance.data[i],
								arn: 'arn:aws:sagemaker:'+region+':'+ownerId+':security-group/'+describeNotebookInstance.data[i]
							});
						}
					}
				}
			}

			// For Workspaces
			var describeWorkspaceDirectories = helpers.addSource(cache, source, ['workspaces', 'describeWorkspaceDirectories', region]);

			if (describeWorkspaceDirectories) {
				if (describeWorkspaceDirectories.err || !describeWorkspaceDirectories.data) {
					helpers.addResult(results, 3, 'Unable to query for workspaces: ' + helpers.addError(describeWorkspaceDirectories), region);
				} else {
					for (i in describeWorkspaceDirectories.data){
						if(inuseSecurityGroups.indexOf(describeWorkspaceDirectories.data[i].WorkspaceSecurityGroupId) == -1) {
							inuseSecurityGroups.push({
								serviceName: 'workspaces',
								secGroupId: describeWorkspaceDirectories.data[i].WorkspaceSecurityGroupId,
								arn: 'arn:aws:workspaces:'+region+':'+ownerId+':security-group/'+describeWorkspaceDirectories.data[i].WorkspaceSecurityGroupId
							});
						}
					}
				}
			}

			async.each(describeMountTargetsData, function(mountTarget, mtcb){

				var describeMountTargetSecurityGroups = helpers.addSource(cache, source, ['efs', 'describeMountTargetSecurityGroups', region, mountTarget.MountTargetId]);

				if (!describeMountTargetSecurityGroups || describeMountTargetSecurityGroups.err || !describeMountTargetSecurityGroups.data) {
					helpers.addResult(results, 3,
						'Unable to query for EFS mount target security groups: ' + mountTarget.MountTargetId + ': ' + helpers.addError(describeMountTargetSecurityGroups), region);
					return mtcb();
				}

				for (i in describeMountTargetSecurityGroups.data){
					if(inuseSecurityGroups.indexOf(describeMountTargetSecurityGroups.data[i]) == -1) {
						inuseSecurityGroups.push({
							serviceName: 'efs',
							secGroupId: describeMountTargetSecurityGroups.data[i],
							arn: 'arn:aws:efs:'+region+':'+ownerId+':security-group/'+describeMountTargetSecurityGroups.data[i]
						});
					}
				}
				
				mtcb();
			}, function(){

				for(i in securityGroups) {

					var inuse = false;
					var arn = 'arn:aws:ec2:' + region + ':' + securityGroups[i].OwnerId + ':security-group/' + securityGroups[i].GroupId;

					for(j in inuseSecurityGroups) {
						if(inuseSecurityGroups[j].secGroupId == securityGroups[i].GroupId) {
							inuse = true;
							break;
						}
					}

					if(!inuse)
						helpers.addResult(results, 2, 'Not used security group: ' + securityGroups[i].GroupName, region, arn);
				}

				rcb();
			});
		}, function(){
			callback(null, results, source);
		});
	}
};