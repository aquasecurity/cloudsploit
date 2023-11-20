var expect = require('chai').expect;
const defaultVpcInUse = require('./defaultVpcInUse');

const describeVpcs =[
    {
        "CidrBlock": "10.0.0.0/16",
        "DhcpOptionsId": "dopt-02f23068a9f47e67e",
        "State": "available",
        "VpcId": "vpc-0d04138d1a5d1ddba",
        "OwnerId": "101363889637",
        "InstanceTenancy": "default",
        "CidrBlockAssociationSet": [
            {
                "AssociationId": "vpc-cidr-assoc-03102f76bafa1b6c9",
                "CidrBlock": "10.0.0.0/16",
                "CidrBlockState": {
                    "State": "associated"
                }
            }
        ],
        "IsDefault": false,
        "Tags": [
            {
                "Key": "Name",
                "Value": "dev-vpc"
            }
        ]
    },
    {
        "CidrBlock": "10.0.0.0/16",
        "DhcpOptionsId": "dopt-02f23068a9f47e67e",
        "State": "available",
        "VpcId": "vpc-123",
        "OwnerId": "101363889637",
        "InstanceTenancy": "default",
        "CidrBlockAssociationSet": [
            {
                "AssociationId": "vpc-cidr-assoc-0195ffaae48916244",
                "CidrBlock": "10.0.0.0/16",
                "CidrBlockState": {
                    "State": "associated"
                }
            }
        ],
        "IsDefault": true,
        "Tags": []
    }
];

const describeInstances = [
    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-02354e95b39ca8dec",
                "InstanceId": "i-03afb9daa31f31bb0",
                "InstanceType": "t2.micro",
                "KeyName": "auto-scaling-test-instance",
                "LaunchTime": "2020-08-31T23:52:43.000Z",
                "Monitoring": {
                    "State": "disabled"
                },
                "Placement": {
                    "AvailabilityZone": "us-east-1e",
                    "GroupName": "",
                    "Tenancy": "default"
                },
                "PrivateDnsName": "ip-172-31-54-187.ec2.internal",
                "PrivateIpAddress": "172.31.54.187",
                "ProductCodes": [],
                "PublicDnsName": "",
                "State": {
                    "Code": 80,
                    "Name": "stopped"
                },
                "StateTransitionReason": "User initiated (2020-09-01 03:39:08 GMT)",
                "SubnetId": "subnet-6a8b635b",
                "VpcId": "vpc-99de2fe4",
                "Architecture": "x86_64",
                "BlockDeviceMappings": [
                    {
                        "DeviceName": "/dev/xvda",
                        "Ebs": {
                            "AttachTime": "2020-08-25T02:21:49.000Z",
                            "DeleteOnTermination": true,
                            "Status": "attached",
                            "VolumeId": "vol-025b523c155020b10"
                        }
                    }
                ],
                "ClientToken": "",
                "EbsOptimized": false,
                "EnaSupport": true,
                "Hypervisor": "xen",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::111122223333:instance-profile/AmazonSSMRoleForInstancesQuickSetup",
                    "Id": "AIPAYE32SRU53G7VOI2UM"
                },
                "NetworkInterfaces": [
                    {
                        "Attachment": {
                            "AttachTime": "2020-08-25T02:21:48.000Z",
                            "AttachmentId": "eni-attach-077c0f4c969c20b4c",
                            "DeleteOnTermination": true,
                            "DeviceIndex": 0,
                            "Status": "attached"
                        },
                        "Description": "",
                        "Groups": [
                            {
                                "GroupName": "launch-wizard-4",
                                "GroupId": "sg-0174d5e394e23015e"
                            }
                        ],
                        "Ipv6Addresses": [],
                        "MacAddress": "06:22:7f:a4:48:f3",
                        "NetworkInterfaceId": "eni-0a53de7b449ed51e0",
                        "OwnerId": "111122223333",
                        "PrivateDnsName": "ip-172-31-54-187.ec2.internal",
                        "PrivateIpAddress": "172.31.54.187",
                        "PrivateIpAddresses": [
                            {
                                "Primary": true,
                                "PrivateDnsName": "ip-172-31-54-187.ec2.internal",
                                "PrivateIpAddress": "172.31.54.187"
                            }
                        ],
                        "SourceDestCheck": true,
                        "Status": "in-use",
                        "SubnetId": "subnet-6a8b635b",
                        "VpcId": "vpc-99de2fe4",
                        "InterfaceType": "interface"
                    }
                ],
                "RootDeviceName": "/dev/xvda",
                "RootDeviceType": "ebs",
                "SecurityGroups": [
                    {
                        "GroupName": "launch-wizard-4",
                        "GroupId": "sg-0174d5e394e23015e"
                    }
                ],
                "SourceDestCheck": true,
                "StateReason": {
                    "Code": "Client.UserInitiatedShutdown",
                    "Message": "Client.UserInitiatedShutdown: User initiated shutdown"
                },
                "Tags": [
                    {
                        "Key": "Name",
                        "Value": "sploit-959-test-instance"
                    }
                ],
                "VirtualizationType": "hvm",
                "CpuOptions": {
                    "CoreCount": 1,
                    "ThreadsPerCore": 1
                },
                "CapacityReservationSpecification": {
                    "CapacityReservationPreference": "open"
                },
                "HibernationOptions": {
                    "Configured": false
                },
                "MetadataOptions": {
                    "State": "applied",
                    "HttpTokens": "optional",
                    "HttpPutResponseHopLimit": 1,
                    "HttpEndpoint": "enabled"
                }
            }
        ],
        "OwnerId": "111122223333",
        "ReservationId": "r-073e1215b28407ada"
    },
    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-02354e95b39ca8dec",
                "InstanceId": "i-03afb9daa31f31bb0",
                "InstanceType": "t2.micro",
                "KeyName": "auto-scaling-test-instance",
                "LaunchTime": "2020-08-31T23:52:43.000Z",
                "Monitoring": {
                    "State": "disabled"
                },
                "Placement": {
                    "AvailabilityZone": "us-east-1e",
                    "GroupName": "",
                    "Tenancy": "default"
                },
                "PrivateDnsName": "ip-172-31-54-187.ec2.internal",
                "PrivateIpAddress": "172.31.54.187",
                "ProductCodes": [],
                "PublicDnsName": "",
                "State": {
                    "Code": 80,
                    "Name": "stopped"
                },
                "StateTransitionReason": "User initiated (2020-09-01 03:39:08 GMT)",
                "SubnetId": "subnet-6a8b635b",
                "VpcId": "vpc-123",
                "Architecture": "x86_64",
                "BlockDeviceMappings": [
                    {
                        "DeviceName": "/dev/xvda",
                        "Ebs": {
                            "AttachTime": "2020-08-25T02:21:49.000Z",
                            "DeleteOnTermination": true,
                            "Status": "attached",
                            "VolumeId": "vol-025b523c155020b10"
                        }
                    }
                ],
                "ClientToken": "",
                "EbsOptimized": false,
                "EnaSupport": true,
                "Hypervisor": "xen",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::111122223333:instance-profile/AmazonSSMRoleForInstancesQuickSetup",
                    "Id": "AIPAYE32SRU53G7VOI2UM"
                },
                "NetworkInterfaces": [
                    {
                        "Attachment": {
                            "AttachTime": "2020-08-25T02:21:48.000Z",
                            "AttachmentId": "eni-attach-077c0f4c969c20b4c",
                            "DeleteOnTermination": true,
                            "DeviceIndex": 0,
                            "Status": "attached"
                        },
                        "Description": "",
                        "Groups": [
                            {
                                "GroupName": "launch-wizard-4",
                                "GroupId": "sg-0174d5e394e23015e"
                            }
                        ],
                        "Ipv6Addresses": [],
                        "MacAddress": "06:22:7f:a4:48:f3",
                        "NetworkInterfaceId": "eni-0a53de7b449ed51e0",
                        "OwnerId": "111122223333",
                        "PrivateDnsName": "ip-172-31-54-187.ec2.internal",
                        "PrivateIpAddress": "172.31.54.187",
                        "PrivateIpAddresses": [
                            {
                                "Primary": true,
                                "PrivateDnsName": "ip-172-31-54-187.ec2.internal",
                                "PrivateIpAddress": "172.31.54.187"
                            }
                        ],
                        "SourceDestCheck": true,
                        "Status": "in-use",
                        "SubnetId": "subnet-6a8b635b",
                        "VpcId": "vpc-123",
                        "InterfaceType": "interface"
                    }
                ],
                "RootDeviceName": "/dev/xvda",
                "RootDeviceType": "ebs",
                "SecurityGroups": [
                    {
                        "GroupName": "launch-wizard-4",
                        "GroupId": "sg-0174d5e394e23015e"
                    }
                ],
                "SourceDestCheck": true,
                "StateReason": {
                    "Code": "Client.UserInitiatedShutdown",
                    "Message": "Client.UserInitiatedShutdown: User initiated shutdown"
                },
                "Tags": [],
                "VirtualizationType": "hvm",
                "CpuOptions": {
                    "CoreCount": 1,
                    "ThreadsPerCore": 1
                },
                "CapacityReservationSpecification": {
                    "CapacityReservationPreference": "open"
                },
                "HibernationOptions": {
                    "Configured": false
                },
                "MetadataOptions": {
                    "State": "applied",
                    "HttpTokens": "optional",
                    "HttpPutResponseHopLimit": 1,
                    "HttpEndpoint": "enabled"
                }
            }
        ],
        "OwnerId": "111122223333",
        "ReservationId": "r-073e1215b28407ada"
    }
];

const describeLoadBalancers = [
    {
        "LoadBalancerName": "test-84",
        "DNSName": "test-84-1988801627.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneName": "test-84-1988801627.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneNameID": "Z35SXDOTRQ7X7K",
        "ListenerDescriptions": [
            {
                "Listener": {
                    "Protocol": "HTTPS",
                    "LoadBalancerPort": 443,
                    "InstanceProtocol": "HTTPS",
                    "InstancePort": 443,
                    "SSLCertificateId": "arn:aws:iam::111122223333:server-certificate/ExampleCertificate"
                },
                "PolicyNames": [
                    "AWSConsole-SSLNegotiationPolicy-test-84-2-1601842068416"
                ]
            }
        ],
        "Policies": {
            "AppCookieStickinessPolicies": [],
            "LBCookieStickinessPolicies": [],
            "OtherPolicies": []
        },
        "BackendServerDescriptions": [],
        "AvailabilityZones": [
            "us-east-1f",
            "us-east-1e",
            "us-east-1d",
            "us-east-1c",
            "us-east-1b",
            "us-east-1a"
        ],
        "Subnets": [
            "subnet-06aa0f60",
            "subnet-673a9a46",
            "subnet-6a8b635b",
            "subnet-aac6b3e7",
            "subnet-c21b84cc",
            "subnet-e83690b7"
        ],
        "VPCId": "vpc-99de2fe4",
        "Instances": [
            {
                "InstanceId": "i-093267d7a579c4bee",
                "InstanceType": "t2.micro",
                "AvailabilityZone": "us-east-1a",
                "LifecycleState": "InService",
                "HealthStatus": "Healthy",
                "LaunchTemplate": {
                    "LaunchTemplateId": "lt-0f1f6b356027abc86",
                    "LaunchTemplateName": "auto-scaling-template",
                    "Version": "1"
                },
                "ProtectedFromScaleIn": false
            }
        ],
        "HealthCheck": {
            "Target": "HTTP:80/index.html",
            "Interval": 30,
            "Timeout": 5,
            "UnhealthyThreshold": 2,
            "HealthyThreshold": 10
        },
        "SourceSecurityGroup": {
            "OwnerAlias": "111122223333",
            "GroupName": "default"
        },
        "SecurityGroups": [
            "sg-aa941691"
        ],
        "CreatedTime": "2020-10-01T17:50:43.330Z",
        "Scheme": "internet-facing"
    },
    {
        "LoadBalancerName": "test-82",
        "DNSName": "test-82-1988801627.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneName": "test-84-1988801627.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneNameID": "Z35SXDOTRQ7X7K",
        "ListenerDescriptions": [
            {
                "Listener": {
                    "Protocol": "HTTPS",
                    "LoadBalancerPort": 443,
                    "InstanceProtocol": "HTTPS",
                    "InstancePort": 443,
                    "SSLCertificateId": "arn:aws:iam::111122223333:server-certificate/ExampleCertificate"
                },
                "PolicyNames": [
                    "AWSConsole-SSLNegotiationPolicy-test-84-2-1601842068416"
                ]
            }
        ],
        "Policies": {
            "AppCookieStickinessPolicies": [],
            "LBCookieStickinessPolicies": [],
            "OtherPolicies": []
        },
        "BackendServerDescriptions": [],
        "AvailabilityZones": [
            "us-east-1f",
            "us-east-1e",
            "us-east-1d",
            "us-east-1c",
            "us-east-1b",
            "us-east-1a"
        ],
        "Subnets": [
            "subnet-06aa0f60",
            "subnet-673a9a46",
            "subnet-6a8b635b",
            "subnet-aac6b3e7",
            "subnet-c21b84cc",
            "subnet-e83690b7"
        ],
        "VPCId": "vpc-123",
        "Instances": [
            {
                "InstanceId": "i-093267d7a579c4bee",
                "InstanceType": "t2.micro",
                "AvailabilityZone": "us-east-1a",
                "LifecycleState": "InService",
                "HealthStatus": "Healthy",
                "LaunchTemplate": {
                    "LaunchTemplateId": "lt-0f1f6b356027abc86",
                    "LaunchTemplateName": "auto-scaling-template",
                    "Version": "1"
                },
                "ProtectedFromScaleIn": false
            }
        ],
        "HealthCheck": {
            "Target": "HTTP:80/index.html",
            "Interval": 30,
            "Timeout": 5,
            "UnhealthyThreshold": 2,
            "HealthyThreshold": 10
        },
        "SourceSecurityGroup": {
            "OwnerAlias": "111122223333",
            "GroupName": "default"
        },
        "SecurityGroups": [
            "sg-aa941691"
        ],
        "CreatedTime": "2020-10-01T17:50:43.330Z",
        "Scheme": "internet-facing"
    }
];

const listFunctions = [
    {
        "FunctionName": "test-lambda",
        "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:test-lambda",
        "Runtime": "nodejs12.x",
        "Role": "arn:aws:iam::000011112222:role/lambda-role",
        "Handler": "index.handler",
        "VpcConfig": {
            "SubnetIds": [
                "subnet-6a8b635b",
                "subnet-c21b84cc"
            ],
            "SecurityGroupIds": [
                "sg-001639e564442dfec"
            ],
            "VpcId": "vpc-99de2fe4"
        },
    },
    {
        "FunctionName": "testing-123",
        "FunctionArn": "arn:aws:lambda:us-east-1:000011112222:function:testing-123",
        "Runtime": "nodejs4.3",
        "Role": "arn:aws:iam::000011112222:role/service-role/testing-123-role-7t7oo29b",
        "Handler": "index.handler",
        "VpcConfig":{
            "VpcId": "vpc-123"
        }
    }
];

const describeDBInstances = [
    {
        DBInstanceIdentifier: 'test-1',
        DBInstanceClass: 'db.t3.micro',
        Engine: 'postgres',
        DBInstanceStatus: 'available',
        MasterUsername: 'postgres',
        Endpoint: {
            Address: 'test-1.cscif9l5pu36.us-east-1.rds.amazonaws.com',
            Port: 5432,
            HostedZoneId: 'Z2R2ITUGPM61AM'
        },
        AvailabilityZone: 'us-east-1a',
        DBSubnetGroup: {
            DBSubnetGroupName: 'default-vpc-112223344',
            DBSubnetGroupDescription: 'Created from the Neptune Management Console',
            VpcId: 'vpc-112223344',
            SubnetGroupStatus: 'Complete',
            Subnets: [Array],
            SupportedNetworkTypes: []
        },
        PreferredMaintenanceWindow: 'mon:07:45-mon:08:15',
        PendingModifiedValues: {},
        StorageEncrypted: true,
        DBInstanceArn: 'arn:aws:rds:us-east-1:5566441122:db:test-1',
        TagList: [],
        DBInstanceAutomatedBackupsReplications: [],
        CustomerOwnedIpEnabled: false,
        ActivityStreamStatus: 'stopped',
        BackupTarget: 'region',
        NetworkType: 'IPV4'
    },
    {
        DBInstanceIdentifier: 'test2-1',
        DBInstanceClass: 'db.t3.micro',
        Engine: 'postgres',
        DBInstanceStatus: 'available',
        MasterUsername: 'postgres',
        Endpoint: {
            Address: 'test2-1.cscif9l5pu36.us-east-1.rds.amazonaws.com',
            Port: 5432,
            HostedZoneId: 'Z2R2ITUGPM61AM'
        },
        AvailabilityZone: 'us-east-1a',
        DBSubnetGroup: {
            DBSubnetGroupName: 'default-vpc-123',
            DBSubnetGroupDescription: 'Created from the Neptune Management Console',
            VpcId: 'vpc-123',
            SubnetGroupStatus: 'Complete',
            Subnets: [Array],
            SupportedNetworkTypes: []
        },
        PreferredMaintenanceWindow: 'mon:07:45-mon:08:15',
        PendingModifiedValues: {},
        StorageEncrypted: true,
        DBInstanceArn: 'arn:aws:rds:us-east-1:5566441122:db:test2-1',
        TagList: [{key: "Key", value: "value"}],
        DBInstanceAutomatedBackupsReplications: [],
        CustomerOwnedIpEnabled: false,
        ActivityStreamStatus: 'stopped',
        BackupTarget: 'region',
        NetworkType: 'IPV4'
    },
];
const describeClusters = [
    {
        "ClusterIdentifier": "redshift-cluster-1",
        "NodeType": "dc2.large",
        "ClusterStatus": "available",
        "ClusterAvailabilityStatus": "Available",
        "MasterUsername": "customuser",
        "DBName": "dev",
        "Endpoint": {
            "Address": "redshift-cluster-1.cks44thktt7l.us-east-1.redshift.amazonaws.com",
            "Port": 5555
        },
        "ClusterCreateTime": "2020-11-25T00:37:51.472000+00:00",
        "AutomatedSnapshotRetentionPeriod": 1,
        "ManualSnapshotRetentionPeriod": -1,
        "ClusterSecurityGroups": [],
        "VpcSecurityGroups": [
            {
                "VpcSecurityGroupId": "sg-aa941691",
                "Status": "active"
            }
        ],
        "ClusterParameterGroups": [
            {
                "ParameterGroupName": "default.redshift-1.0",
                "ParameterApplyStatus": "in-sync"
            }
        ],
        "ClusterSubnetGroupName": "default",
        "VpcId": "vpc-99de2fe4",
        "AvailabilityZone": "us-east-1c",
        "PreferredMaintenanceWindow": "sun:00:00-sun:00:30",
        "PendingModifiedValues": {},
        "ClusterVersion": "1.0",
        "AllowVersionUpgrade": true,
        "NumberOfNodes": 1,
        "PubliclyAccessible": false,
        "Encrypted": false,
        "ClusterPublicKey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfPK8qflrCru2M5kL3A7i0tIj+FAPOVLdrDm7vPwhAWBNKQlfqmt4+a8ob+Ql7Hrlu+pu8eYdFFjzcmRtsI9m3onlbQ6jIKiW6WwsqYvPSucPq/78rFYGcxrGc213OL2XF1xZnZTpGleeH/BH1q/7hTiwYVmZ17k3ZL320jRUTFm2WEvcQoDWu8DderPPjllJ7Zz/JtJx1x3XM5kP9e4zSSWaUfAG3kKKxDeHbNUAq5JRk/yYA8iel1I7qIbl6NZpDgOOgLI9fUmICwH0u740PEDVoSrh2qFepQgMnRg1sPgdvoPFaSIpiQzNwUNqQiZhNstZDWu73Fjyqzv9m7ZxH Amazon-Redshift\n",
        "ClusterNodes": [
            {
                "NodeRole": "SHARED",
                "PrivateIPAddress": "172.31.22.110",
                "PublicIPAddress": "52.73.49.144"
            }
        ],
        "ClusterRevisionNumber": "21262",
        "Tags": [],
        "EnhancedVpcRouting": false,
        "IamRoles": [],
        "MaintenanceTrackName": "current",
        "DeferredMaintenanceWindows": [],
        "NextMaintenanceWindowStartTime": "2020-11-29T00:00:00+00:00",
        "ClusterNamespaceArn": "arn:aws:redshift:us-east-1:111122223333:namespace:f862b236-268d-4e86-afd3-ef91e96a97c4"
    },
    {
        "ClusterIdentifier": "redshift-cluster-2",
        "NodeType": "dc2.large",
        "ClusterStatus": "available",
        "ClusterAvailabilityStatus": "Available",
        "MasterUsername": "awsuser",
        "DBName": "dev",
        "Endpoint": {
            "Address": "redshift-cluster-1.cks44thktt7l.us-east-1.redshift.amazonaws.com",
            "Port": 5439
        },

        "ClusterCreateTime": "2020-11-25T00:37:51.472000+00:00",
        "AutomatedSnapshotRetentionPeriod": 0,
        "ManualSnapshotRetentionPeriod": -1,
        "ClusterSecurityGroups": [],
        "VpcSecurityGroups": [
            {
                "VpcSecurityGroupId": "sg-aa941691",
                "Status": "active"
            }
        ],
        "ClusterParameterGroups": [
            {
                "ParameterGroupName": "default.redshift-1.0",
                "ParameterApplyStatus": "in-sync"
            }
        ],
        "ClusterSubnetGroupName": "default",
        "VpcId":"vpc-123",
        "AvailabilityZone": "us-east-1c",
        "PreferredMaintenanceWindow": "sun:00:00-sun:00:30",
        "PendingModifiedValues": {},
        "ClusterVersion": "1.0",
        "AllowVersionUpgrade": true,
        "NumberOfNodes": 1,
        "PubliclyAccessible": false,
        "Encrypted": false,
        "ClusterPublicKey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfPK8qflrCru2M5kL3A7i0tIj+FAPOVLdrDm7vPwhAWBNKQlfqmt4+a8ob+Ql7Hrlu+pu8eYdFFjzcmRtsI9m3onlbQ6jIKiW6WwsqYvPSucPq/78rFYGcxrGc213OL2XF1xZnZTpGleeH/BH1q/7hTiwYVmZ17k3ZL320jRUTFm2WEvcQoDWu8DderPPjllJ7Zz/JtJx1x3XM5kP9e4zSSWaUfAG3kKKxDeHbNUAq5JRk/yYA8iel1I7qIbl6NZpDgOOgLI9fUmICwH0u740PEDVoSrh2qFepQgMnRg1sPgdvoPFaSIpiQzNwUNqQiZhNstZDWu73Fjyqzv9m7ZxH Amazon-Redshift\n",
        "ClusterNodes": [
            {
                "NodeRole": "SHARED",
                "PrivateIPAddress": "172.31.22.110",
                "PublicIPAddress": "52.73.49.144"
            }
        ],
        "ClusterRevisionNumber": "21262",
        "Tags": [],
        "EnhancedVpcRouting": false,
        "IamRoles": [],
        "MaintenanceTrackName": "current",
        "DeferredMaintenanceWindows": [],
        "NextMaintenanceWindowStartTime": "2020-11-29T00:00:00+00:00",
        "ClusterNamespaceArn": "arn:aws:redshift:us-east-1:111122223333:namespace:f862b236-268d-4e86-afd3-ef91e96a97c4"
    }
];

const createCache =(vpcs,instances,loadbalancers,listfunctions,dbinstance,cluster) =>
{
    return {
        ec2:{
            describeVpcs:{
                'us-east-1':{
                    data:vpcs
                }
            },
            describeInstances: {
                'us-east-1':{
                    data:instances
                }
            }
        },
        elb:{
            describeLoadBalancers: {
                'us-east-1':{
                    data:loadbalancers
                }
            }
        },
        lambda:{
            listFunctions: {
                'us-east-1':{
                    data:listfunctions
                }
            }
        },
        rds:{
            describeDBInstances: {
                'us-east-1':{
                    data:dbinstance
                }
            }
        },
        redshift:{
            describeClusters: {
                'us-east-1': {
                    data: cluster
                }
            }
        }
    }
}


const createNullCache =(vpcs,instances,loadbalancers,listfunctions,dbinstance,cluster) =>
{
    return {
        ec2:{
            describeVpcs:{
                'us-east-1': null
            },
            describeInstances: {
                'us-east-1': null
            }
        },
        elb:{
            describeLoadBalancers: {
                'us-east-1': null
            }
        },
        lambda:{
            listFunctions: {
                'us-east-1': null
            }
        },
        rds:{
            describeDBInstances: {
                'us-east-1':null
            }
        },
        redshift:{
            describeClusters: {
                'us-east-1': null
            }
        }
    }
}

const createErrorCache =(vpcs,instances,loadbalancers,listfunctions,dbinstance,cluster) =>
{
    return {
        ec2:{
            describeVpcs:{
                'us-east-1':{
                    err:{
                        message: 'error describing VPC'
                    }
                }
            },
            describeInstances: {
                'us-east-1':{
                    err:{
                        message: 'error describing instance'
                    }
                }
            }
        },
        elb:{
            describeLoadBalancers: {
                'us-east-1':{
                    err:{
                        message: 'error describing loadbalancer'
                    }
                }
            }
        },
        lambda:{
            listFunctions: {
                'us-east-1':{
                    err:{
                        message: 'error listing functions'
                    }
                }
            }
        },
        rds:{
            describeDBInstances: {
                'us-east-1':{
                    err:{
                        message: 'error describing dbinstance'
                    }
                }
            }
        },
        redshift:{
            describeClusters: {
                'us-east-1': {
                    err:{
                        message: 'error describing cluster'
                    }
                }
            }
        }
    }
}


describe('defaultVpcInUse', function () {
    describe('run', function () {
        it('should PASS if no vpc  found', function (done) {
            const cache = createCache([],[],[],[],[]);
            defaultVpcInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No VPCs present');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if default vpc is not in use ', function (done) {
            const cache = createCache(describeVpcs,[describeInstances[0]],[describeDBInstances[0]],[listFunctions[0]],[describeClusters[0]],[describeLoadBalancers[0]]);
            defaultVpcInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Default VPC is not in use');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if default vpc is in use ', function (done) {
            const cache = createCache(describeVpcs,[describeInstances[1]],[describeDBInstances[1]],[listFunctions[1]],[describeClusters[1]],[describeLoadBalancers[1]]);
            defaultVpcInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Default VPC is in use');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if error occur while describe VPC or EC2 Instance or db Instance or list function or cluster or elb ', function (done) {
            const cache= createErrorCache();
            defaultVpcInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return any results if unable to fetch VPC or EC2 Instance or db Instance or list function or cluster or elb', function (done) {
            const cache = createNullCache();
            defaultVpcInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
