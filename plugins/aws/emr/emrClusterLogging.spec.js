const expect = require('chai').expect;
const emrClusterLogging = require('./emrClusterLogging');

const listClusters = [
    {
        "Id": "j-BH72QI9T25CL",
        "Name": "emr-cluster-1",
        "Status": {
          "State": "TERMINATED_WITH_ERRORS",
          "StateChangeReason": {
            "Code": "INTERNAL_ERROR",
            "Message": "Failed to start the job flow due to an internal error"
          },
          "Timeline": {
            "CreationDateTime": "2020-09-17T09:43:13.125Z",
            "EndDateTime": "2020-09-17T09:45:36.643Z"
          }
        },
        "NormalizedInstanceHours": 0,
        "ClusterArn": "arn:aws:elasticmapreduce:us-east-1:123456654321:cluster/j-BH72QI9T25CL"
    },
    {
        Id: 'j-2FO4W2DL7JJAM',
        Name: 'emr-cluster-2',
        Status: {
          State: 'TERMINATED_WITH_ERRORS',
          StateChangeReason: {
            Code: 'BOOTSTRAP_FAILURE',
            Message: 'On the master instance (i-0ddd5cacbc6b0082c), application provisioning timed out'
          },
          Timeline: {
            CreationDateTime: '2020-09-08T11:36:07.027Z',
            EndDateTime: '2020-09-08T11:52:29.966Z'
          }
        },
        NormalizedInstanceHours: 0,
        ClusterArn: 'arn:aws:elasticmapreduce:us-east-1:123456654321:cluster/j-2FO4W2DL7JJAM'
    }
];

const describeCluster = [
    {
        Cluster: {
          Id: 'j-BH72QI9T25CL',
          Name: 'emr-cluster-1',
          Status: [Object],
          Ec2InstanceAttributes: [Object],
          InstanceCollectionType: 'INSTANCE_GROUP',
          LogUri: 's3n://aws-logs-123456654321-us-east-1/elasticmapreduce/',
          ReleaseLabel: 'emr-5.30.1',
          AutoTerminate: false,
          TerminationProtected: true,
          VisibleToAllUsers: true,
          Applications: [Array],
          Tags: [],
          ServiceRole: 'EMR_DefaultRole',
          NormalizedInstanceHours: 0,
          MasterPublicDnsName: 'ec2-3-234-140-67.compute-1.amazonaws.com',
          Configurations: [],
          SecurityConfiguration: 'test-security-100',
          AutoScalingRole: 'EMR_AutoScaling_DefaultRole',
          ScaleDownBehavior: 'TERMINATE_AT_TASK_COMPLETION',
          EbsRootVolumeSize: 10,
          KerberosAttributes: {},
          ClusterArn: 'arn:aws:elasticmapreduce:us-east-1:123456654321:cluster/j-2RF0ACE2SIAWT',
          StepConcurrencyLevel: 1
        }
    },
    {
        Cluster: {
            Id: 'j-2FO4W2DL7JJAM',
            Name: 'emr-cluster-2',
            Status: [Object],
            Ec2InstanceAttributes: [Object],
            InstanceCollectionType: 'INSTANCE_GROUP',
            ReleaseLabel: 'emr-5.30.1',
            AutoTerminate: true,
            TerminationProtected: false,
            VisibleToAllUsers: true,
            Applications: [Array],
            Tags: [],
            ServiceRole: 'EMR_DefaultRole',
            NormalizedInstanceHours: 0,
            MasterPublicDnsName: 'ec2-3-237-81-241.compute-1.amazonaws.com',
            Configurations: [],
            SecurityConfiguration: 'test-sc-100',
            AutoScalingRole: 'EMR_AutoScaling_DefaultRole',
            ScaleDownBehavior: 'TERMINATE_AT_TASK_COMPLETION',
            EbsRootVolumeSize: 10,
            KerberosAttributes: {},
            ClusterArn: 'arn:aws:elasticmapreduce:us-east-1:123456654321:cluster/j-2FO4W2DL7JJAM',
            StepConcurrencyLevel: 1
        }
    }
];

const createCache = (listClusters, describeCluster) => {
    var clusterId = (listClusters && listClusters.length) ? listClusters[0].Id : null;
    return {
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
    };
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
        emr: {
            listClusters: {
                'us-east-1': null,
            },
        },
    };
};

describe('emrClusterLogging', function () {
    describe('run', function () {
        it('should FAIL if EMR cluster logging is not enabled', function (done) {
            const cache = createCache([listClusters[1]], describeCluster[1]);
            emrClusterLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if EMR cluster logging is enabled', function (done) {
            const cache = createCache([listClusters[0]], describeCluster[0]);
            emrClusterLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no EMR clusters found', function (done) {
            const cache = createCache([]);
            emrClusterLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe EMR cluster', function (done) {
            const cache = createDescribeClusterErrorCache(listClusters);
            emrClusterLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list EMR clusters', function (done) {
            const cache = createErrorCache();
            emrClusterLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list clusters response not found', function (done) {
            const cache = createNullCache();
            emrClusterLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
