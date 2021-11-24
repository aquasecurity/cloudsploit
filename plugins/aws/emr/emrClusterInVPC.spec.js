const expect = require('chai').expect;
const emrClusterInVPC = require('./emrClusterInVPC');

const describeAccountAttributes = [
    {
        "AttributeName": "supported-platforms",
        "AttributeValues": [
            {
                "AttributeValue": "VPC"
            }
        ]
    },
    {
        "AttributeName": "supported-platforms",
        "AttributeValues": [
            {
                "AttributeValue": "EC2"
            },
            {
                "AttributeValue": "VPC"
            }
        ]
    },
];

const listClusters = [
    {
        "Id": "j-8PNQXHQF599L",
        "Name": "MyCluster9",
        "Status": {
            "State": "TERMINATED_WITH_ERRORS",
            "StateChangeReason": {
                "Code": "VALIDATION_ERROR",
                "Message": "The requested instance type c1.medium is not supported in the requested availability zone. Learn more at https://docs.aws.amazon.com/console/elasticmapreduce/ERROR_noinstancetype"
            },
            "Timeline": {
                "CreationDateTime": "2021-11-04T02:01:43.422000-07:00",
                "EndDateTime": "2021-11-04T02:03:04.638000-07:00"
            }
        },
        "NormalizedInstanceHours": 0,
        "ClusterArn": "arn:aws:elasticmapreduce:us-east-1:000011112222:cluster/j-8PNQXHQF599L"
    },
    {
        "Id": "j-11W10W1AXKL60",
        "Name": "MyCluster8",
        "Status": {
            "State": "TERMINATED_WITH_ERRORS",
            "StateChangeReason": {
                "Code": "VALIDATION_ERROR",
                "Message": "The requested instance type m1.large is not supported in the requested availability zone. Learn more at https://docs.aws.amazon.com/console/elasticmapreduce/ERROR_noinstancetype"
            }
        }
    }
];

const describeCluster= [
    {
        "Cluster": {
            "Id": "j-8PNQXHQF599L",
            "Name": "MyCluster9",
            "Status": {
                "State": "TERMINATED_WITH_ERRORS",
                "StateChangeReason": {
                    "Code": "VALIDATION_ERROR",
                    "Message": "The requested instance type c1.medium is not supported in the requested availability zone. Learn more at https://docs.aws.amazon.com/console/elasticmapreduce/ERROR_noinstancetype"
                },
                "Timeline": {
                    "CreationDateTime": "2021-11-04T02:01:43.422000-07:00",
                    "EndDateTime": "2021-11-04T02:03:04.638000-07:00"
                }
            },
            "Ec2InstanceAttributes": {
                "Ec2KeyName": "minekp",
                "Ec2SubnetId": "subnet-0970477bd56d55b76",
                "RequestedEc2SubnetIds": [
                    "subnet-0970477bd56d55b76"
                ],
                "Ec2AvailabilityZone": "us-east-1f",
                "RequestedEc2AvailabilityZones": [],
                "IamInstanceProfile": "EMR_EC2_DefaultRole",
                "EmrManagedMasterSecurityGroup": "sg-03e37c1f01b5eeabb",
                "EmrManagedSlaveSecurityGroup": "sg-0f30865beac41d4a3",
                "AdditionalMasterSecurityGroups": [],
                "AdditionalSlaveSecurityGroups": []
            },
        }
    },
    {
        "Cluster": {
            "Id": "j-11W10W1AXKL60",
            "Name": "MyCluster8",
            "Status": {
                "State": "TERMINATED_WITH_ERRORS",
                "StateChangeReason": {
                    "Code": "VALIDATION_ERROR",
                    "Message": "The requested instance type m1.large is not supported in the requested availability zone. Learn more at https://docs.aws.amazon.com/console/elasticmapreduce/ERROR_noinstancetype"
                },
                "Timeline": {
                    "CreationDateTime": "2021-11-03T06:52:10.746000-07:00",
                    "EndDateTime": "2021-11-03T06:53:34.541000-07:00"
                }
            },
            "Ec2InstanceAttributes": {
                "Ec2KeyName": "minekp",
                "Ec2SubnetId": "",
                "RequestedEc2SubnetIds": [
                    ""
                ],
                "Ec2AvailabilityZone": "us-east-1e"
            }
        }
    }
];

const createCache = (attributes,listClusters, describeCluster) => {
    var clusterId = (listClusters && listClusters.length) ? listClusters[0].Id : null;
    return {
        ec2:{
            describeAccountAttributes: {
                'us-east-1': {
                    data: attributes
                },
            },
        },
        emr: {
            listClusters: {
                'us-east-1': {
                    data: listClusters
                }
            },
            describeCluster: {
                'us-east-1': {
                    [clusterId]: {
                        data: describeCluster
                    }
                }
            },
        }
    };
};

const createErrorCache = () => {
    return {
        emr: {
            listClusters: {
                'us-east-1': {
                    err: {
                        message: 'error listing emr clusters'
                    },
                },
            },
        },
    }  
};

const createDescribeClusterErrorCache = (clusters) => {
    return {
        emr: {
            listClusters: {
                'us-east-1': {
                    data: clusters
                },
            },
            describeCluster: {
                'us-east-1': {
                    [clusters[0].ClusterId]: {
                        err: {
                            message: 'error describing EMR cluster'
                        }
                    } 
                }
            }
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeAccountAttributes: {
                'us-east-1': null,
            },
        emr: {
            listClusters: {
                'us-east-1': null,
            },
        },
    }
    };
};

describe('emrClusterInVPC', function () {
    describe('run', function () {
        it('should FAIL if EMR cluster is not in VPC', function (done) {
            const cache = createCache([describeAccountAttributes[1]],[listClusters[1]], describeCluster[1]);
            emrClusterInVPC.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if EMR cluster is in VPC', function (done) {
            const cache = createCache(describeAccountAttributes[0],[listClusters[0]], describeCluster[0]);
            emrClusterInVPC.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no EMR clusters found', function (done) {
            const cache = createCache(describeAccountAttributes[0],[]);
            emrClusterInVPC.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe EMR cluster', function (done) {
            const cache = createDescribeClusterErrorCache(listClusters);
            emrClusterInVPC.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list EMR clusters or account attributes', function (done) {
            const cache = createErrorCache();
            emrClusterInVPC.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list clusters response not found', function (done) {
            const cache = createNullCache();
            emrClusterInVPC.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
