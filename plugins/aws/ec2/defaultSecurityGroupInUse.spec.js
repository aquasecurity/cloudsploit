var expect = require('chai').expect;
const ec2AssociatedWithDefaultSG = require('./defaultSecurityGroupInUse');

describeInstances = [
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
              
                "ClientToken": "",
                "EbsOptimized": false,
                "EnaSupport": true,
                "Hypervisor": "xen",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::111122223333:instance-profile/AmazonSSMRoleForInstancesQuickSetup",
                    "Id": "AIPAYE32SRU53G7VOI2UM"
                },
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
                "VpcId": "vpc-99de2fe4",
                "Architecture": "x86_64",
                "ClientToken": "",
                "EbsOptimized": false,
                "EnaSupport": true,
                "Hypervisor": "xen",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::111122223333:instance-profile/AmazonSSMRoleForInstancesQuickSetup",
                    "Id": "AIPAYE32SRU53G7VOI2UM"
                },
                "RootDeviceName": "/dev/xvda",
                "RootDeviceType": "ebs",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
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
]

const createCache = (groups) => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': {
                    data: groups
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing security groups'
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': null,
            },
        },
    };
};

describe('ec2AssociatedWithDefaultSG', function () {
    describe('run', function () {
          it('should PASS if EC2 is not associated with default security group', function (done) {
              const cache = createCache([describeInstances[0]]);
              ec2AssociatedWithDefaultSG.run(cache, {}, (err, results) => {
                  expect(results.length).to.equal(1);
                  expect(results[0].status).to.equal(0);
                  expect(results[0].region).to.equal('us-east-1')
                  expect(results[0].message).to.include('EC2 instance is not associated with default security group');
                  done();
              });
          });

          // it('should FAIL if EC2 is associated with default security group', function (done) {
          //    const cache = createCache([describeInstances[1]]);
          //    ec2AssociatedWithDefaultSG.run(cache, {}, (err, results) => {
          //        expect(results.length).to.equal(1);
          //        expect(results[0].status).to.equal(2);
          //        expect(results[0].region).to.equal('us-east-1')
          //        expect(results[0].message).to.include('EC2 instance is associated with default security group');
          //        done();
          //    });
          // });

        it('should PASS if no security groups found', function (done) {
            const cache = createCache([]);
            ec2AssociatedWithDefaultSG.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1')
                expect(results[0].message).to.include('No EC2 instances found');
                done();
            });
        });

        it('should UNKNWON unable to describe security groups', function (done) {
            const cache = createErrorCache();
            ec2AssociatedWithDefaultSG.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1')
                expect(results[0].message).to.include('Unable to query for instances:');
                done();
            });
        });

        it('should not return anything if describe security groups response not found', function (done) {
            const cache = createNullCache();
            ec2AssociatedWithDefaultSG.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
