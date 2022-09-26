const expect = require('chai').expect;
const enableDetailMonitoring = require('./enableDetailmonitoring.js');

describeInstances = [
	{
		Groups: [],
		Instances: [
			{
				AmiLaunchIndex: 0,
				ImageId: 'ami-0022f774911c1d690',
				InstanceId: 'i-02d03efaa61cec2b4',
				InstanceType: 't2.micro',
				KeyName: 'test',
				LaunchTime: '2022-06-21T13:19:06+00:00',
				Monitoring: {
					State: 'disabled'
				},
				Placement: {
					AvailabilityZone: 'us-east-1b',
					GroupName: '',
					Tenancy: 'default'
				},
				PrivateDnsName: 'ip-172-31-26-67.ec2.internal',
				PrivateIpAddress: '172.31.26.67',
				ProductCodes: [],
				PublicDnsName: 'ec2-34-227-65-93.compute-1.amazonaws.com',
				PublicIpAddress: '34.227.65.93',
				State: {
					Code: 16,
					Name: 'running'
				},
				StateTransitionReason: '',
				SubnetId: 'subnet-06629b4200870c740',
				VpcId: 'vpc-0f4f4575a74fac014',
				Architecture: 'x86_64',
				BlockDeviceMappings: [
					{
						DeviceName: '/dev/xvda',
						Ebs: {
							AttachTime: '2022-05-11T02:25:08+00:00',
							DeleteOnTermination: true,
							Status: 'attached',
							VolumeId: 'vol-03ee01300d509ba9f'
						}
					}
				],
				ClientToken: '',
				EbsOptimized: false,
				EnaSupport: true,
				Hypervisor: 'xen',
				IamInstanceProfile: {
					Arn: 'arn:aws:iam::101363889637:instance-profile/AmazonSSMRoleForInstancesQuickSetup',
					Id: 'AIPARPGOCGXS55MJYEHU6'
				},
				NetworkInterfaces: [
					{
						Association: {
							IpOwnerId: 'amazon',
							PublicDnsName: 'ec2-34-227-65-93.compute-1.amazonaws.com',
							PublicIp: '34.227.65.93'
						},
						Attachment: {
							AttachTime: '2022-05-11T02:25:07+00:00',
							AttachmentId: 'eni-attach-02090cccb6068e133',
							DeleteOnTermination: true,
							DeviceIndex: 0,
							Status: 'attached',
							NetworkCardIndex: 0
						},
						Description: '',
						Groups: [
							{
								GroupName: 'launch-wizard-4',
								GroupId: 'sg-0feda0342bbe37661'
							}
						],
						Ipv6Addresses: [],
						MacAddress: '0a:48:06:61:f1:c5',
						NetworkInterfaceId: 'eni-0e53af86b785956a2',
						OwnerId: '101363889637',
						PrivateDnsName: 'ip-172-31-26-67.ec2.internal',
						PrivateIpAddress: '172.31.26.67',
						PrivateIpAddresses: [
							{
								Association: {
									IpOwnerId: 'amazon',
									PublicDnsName: 'ec2-34-227-65-93.compute-1.amazonaws.com',
									PublicIp: '34.227.65.93'
								},
								Primary: true,
								PrivateDnsName: 'ip-172-31-26-67.ec2.internal',
								PrivateIpAddress: '172.31.26.67'
							}
						],
						SourceDestCheck: true,
						Status: 'in-use',
						SubnetId: 'subnet-06629b4200870c740',
						VpcId: 'vpc-0f4f4575a74fac014',
						InterfaceType: 'interface'
					}
				],
				RootDeviceName: '/dev/xvda',
				RootDeviceType: 'ebs',
				SecurityGroups: [
					{
						GroupName: 'launch-wizard-4',
						GroupId: 'sg-0feda0342bbe37661'
					}
				],
				SourceDestCheck: true,
				VirtualizationType: 'hvm',
				CpuOptions: {
					CoreCount: 1,
					ThreadsPerCore: 1
				},
				CapacityReservationSpecification: {
					CapacityReservationPreference: 'open'
				},
				HibernationOptions: {
					Configured: false
				},
				MetadataOptions: {
					State: 'applied',
					HttpTokens: 'optional',
					HttpPutResponseHopLimit: 1,
					HttpEndpoint: 'enabled',
					HttpProtocolIpv6: 'disabled',
					InstanceMetadataTags: 'disabled'
				},
				EnclaveOptions: {
					Enabled: false
				},
				PlatformDetails: 'Linux/UNIX',
				UsageOperation: 'RunInstances',
				UsageOperationUpdateTime: '2022-05-11T02:25:07+00:00',
				PrivateDnsNameOptions: {
					HostnameType: 'ip-name',
					EnableResourceNameDnsARecord: true,
					EnableResourceNameDnsAAAARecord: false
				},
				MaintenanceOptions: {
					AutoRecovery: 'default'
				}
			}]
	},
	{
		Groups: [],
		Instances: [
			{
				AmiLaunchIndex: 0,
				ImageId: 'ami-026b57f3c383c2eec',
				InstanceId: 'i-014684b238c2a2542',
				InstanceType: 't2.micro',
				KeyName: 'key',
				LaunchTime: '2022-09-23T08:04:24+00:00',
				Monitoring: {
					State: 'enabled'
				},
				Placement: {
					AvailabilityZone: 'us-east-1b',
					GroupName: '',
					Tenancy: 'default'
				},
				PrivateDnsName: 'ip-172-31-31-220.ec2.internal',
				PrivateIpAddress: '172.31.31.220',
				ProductCodes: [],
				PublicDnsName: 'ec2-54-221-73-254.compute-1.amazonaws.com',
				PublicIpAddress: '54.221.73.254',
				State: {
					Code: 16,
					Name: 'running'
				},
				StateTransitionReason: '',
				SubnetId: 'subnet-06629b4200870c740',
				VpcId: 'vpc-0f4f4575a74fac014',
				Architecture: 'x86_64',
				BlockDeviceMappings: [
					{
						DeviceName: '/dev/xvda',
						Ebs: {
							AttachTime: '2022-09-23T08:04:25+00:00',
							DeleteOnTermination: true,
							Status: 'attached',
							VolumeId: 'vol-0b51677fba8ac8b68'
						}
					}
				],
				ClientToken: '',
				EbsOptimized: false,
				EnaSupport: true,
				Hypervisor: 'xen',
				NetworkInterfaces: [
					{
						Association: {
							IpOwnerId: 'amazon',
							PublicDnsName: 'ec2-54-221-73-254.compute-1.amazonaws.com',
							PublicIp: '54.221.73.254'
						},
						Attachment: {
							AttachTime: '2022-09-23T08:04:24+00:00',
							AttachmentId: 'eni-attach-013f20b1c88b953f2',
							DeleteOnTermination: true,
							DeviceIndex: 0,
							Status: 'attached',
							NetworkCardIndex: 0
						},
						Description: '',
						Groups: [
							{
								GroupName: 'launch-wizard-5',
								GroupId: 'sg-07c71866f78b2dbf2'
							}
						],
						Ipv6Addresses: [],
						MacAddress: '0a:cd:66:5e:74:97',
						NetworkInterfaceId: 'eni-027a688db11a3ca0b',
						OwnerId: '101363889637',
						PrivateDnsName: 'ip-172-31-31-220.ec2.internal',
						PrivateIpAddress: '172.31.31.220',
						PrivateIpAddresses: [
							{
								Association: {
									IpOwnerId: 'amazon',
									PublicDnsName: 'ec2-54-221-73-254.compute-1.amazonaws.com',
									PublicIp: '54.221.73.254'
								},
								Primary: true,
								PrivateDnsName: 'ip-172-31-31-220.ec2.internal',
								PrivateIpAddress: '172.31.31.220'
							}
						],
						SourceDestCheck: true,
						Status: 'in-use',
						SubnetId: 'subnet-06629b4200870c740',
						VpcId: 'vpc-0f4f4575a74fac014',
						InterfaceType: 'interface'
					}
				],
				RootDeviceName: '/dev/xvda',
				RootDeviceType: 'ebs',
				SecurityGroups: [
					{
						GroupName: 'launch-wizard-5',
						GroupId: 'sg-07c71866f78b2dbf2'
					}
				],
				SourceDestCheck: true,
				Tags: [
					{
						Key: 'Name',
						Value: 'test-detailMonitoring'
					}
				],
				VirtualizationType: 'hvm',
				CpuOptions: {
					CoreCount: 1,
					ThreadsPerCore: 1
				},
				CapacityReservationSpecification: {
					CapacityReservationPreference: 'open'
				},
				HibernationOptions: {
					Configured: false
				},
				MetadataOptions: {
					State: 'applied',
					HttpTokens: 'optional',
					HttpPutResponseHopLimit: 1,
					HttpEndpoint: 'enabled',
					HttpProtocolIpv6: 'disabled',
					InstanceMetadataTags: 'disabled'
				},
				EnclaveOptions: {
					Enabled: false
				},
				PlatformDetails: 'Linux/UNIX',
				UsageOperation: 'RunInstances',
				UsageOperationUpdateTime: '2022-09-23T08:04:24+00:00',
				PrivateDnsNameOptions: {
					HostnameType: 'ip-name',
					EnableResourceNameDnsARecord: true,
					EnableResourceNameDnsAAAARecord: false
				},
				MaintenanceOptions: {
					AutoRecovery: 'default'
				}
			}
		],
		OwnerId: '101363889637',
		ReservationId: 'r-065644dc06b2b1443'
	}

];

const createCache = (instances) => {
	return {
		ec2: {
			describeInstances: {
				'us-east-1': {
					data: instances
				}
			}
		}
	};
};

const createErrorCache = () => {
	return {
		ec2: {
			describeInstances: {
				'us-east-1': {
					err: {
						message: 'error'
					}
				}
			}
		}
	};
};

describe('enableDetailMonitoring', function () {
	describe('run', function () {
		it('should PASS if there are no instances', function (done) {
			const cache = createCache([]);
			enableDetailMonitoring.run(cache, {}, (err, results) => {
				expect(results.length).to.equal(1);
				expect(results[0].status).to.equal(0);
				expect(results[0].region).to.equal('us-east-1');
				done();
			});
		});

		it('should UNKNOWN if describeInstances error', function (done) {
			const cache = createErrorCache();
			enableDetailMonitoring.run(cache, {}, (err, results) => {
				expect(results.length).to.equal(1);
				expect(results[0].status).to.equal(3);
				done();
			});
		});

		it('should PASS if EC2 have enabled Detailed Monitoring', function (done) {
			const cache = createCache([describeInstances[1]]);
			enableDetailMonitoring.run(cache, {}, (err, results) => {
				expect(results.length).to.equal(1);
				expect(results[0].status).to.equal(0);
				expect(results[0].region).to.equal('us-east-1');
				done();
			});
		});

		it('should FAIL if EC2 does not have Detailed Monitoring enabled', function (done) {
			const cache = createCache([describeInstances[0]]);
			enableDetailMonitoring.run(cache, {}, (err, results) => {
				expect(results.length).to.equal(1);
				expect(results[0].status).to.equal(2);
				expect(results[0].region).to.equal('us-east-1');
				done();
			});
		});
	});
});
