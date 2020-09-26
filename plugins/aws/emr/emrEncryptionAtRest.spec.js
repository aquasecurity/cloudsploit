const expect = require('chai').expect;
const emrEncryptionAtRest = require('./emrEncryptionAtRest');

const listClusters = [
    {
        "Id": "j-BH72QI9T25CL",
        "Name": "My cluster",
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
        Name: 'My cluster',
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
      },
      {
        Id: 'j-3MTKFUU3FOIOD',
        Name: 'test-cluster-104-1',
        Status: {
          State: 'TERMINATED_WITH_ERRORS',
          StateChangeReason: {
            Code: 'BOOTSTRAP_FAILURE',
            Message: 'On the master instance (i-0b72f161549b8dbe0), application provisioning failed'
          },
          Timeline: {
            CreationDateTime: '2020-09-08T09:29:40.434Z',
            EndDateTime: '2020-09-08T09:37:01.743Z'
          }
        },
        NormalizedInstanceHours: 0,
        ClusterArn: 'arn:aws:elasticmapreduce:us-east-1:123456654321:cluster/j-3MTKFUU3FOIOD'
      },
      {
        Id: 'j-2RF0ACE2SIAWT',
        Name: 'My cluster',
        Status: {
          State: 'TERMINATED_WITH_ERRORS',
          StateChangeReason: {
            Code: 'VALIDATION_ERROR',
            Message: 'On the master instance (i-07c57ec89814ff6fb), Invalid S3Provider: Cannot recognize cacert.pem from the S3Provider zip file.'
          },
          Timeline: {
            CreationDateTime: '2020-09-06T09:55:19.177Z',
            EndDateTime: '2020-09-06T09:59:11.533Z'
          }
        },
        NormalizedInstanceHours: 0,
        ClusterArn: 'arn:aws:elasticmapreduce:us-east-1:123456654321:cluster/j-2RF0ACE2SIAWT'
      }
];

const describeCluster = [
    {
        Cluster: {
          Id: 'j-2RF0ACE2SIAWT',
          Name: 'My cluster',
          Status: [Object],
          Ec2InstanceAttributes: [Object],
          InstanceCollectionType: 'INSTANCE_GROUP',
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
            Name: 'My cluster',
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
    },
    {
        Cluster: {
            Id: 'j-3MTKFUU3FOIOD',
            Name: 'test-cluster-104-1',
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
            MasterPublicDnsName: 'ec2-3-83-21-230.compute-1.amazonaws.com',
            SecurityConfiguration: 'test-sc-100',
            Configurations: [],
            AutoScalingRole: 'EMR_AutoScaling_DefaultRole',
            ScaleDownBehavior: 'TERMINATE_AT_TASK_COMPLETION',
            EbsRootVolumeSize: 10,
            KerberosAttributes: {},
            ClusterArn: 'arn:aws:elasticmapreduce:us-east-1:123456654321:cluster/j-3MTKFUU3FOIOD',
            StepConcurrencyLevel: 1
        }
    },
    {
        Cluster: {
            Id: 'j-2FO4W2DL7JJAM',
            Name: 'My cluster',
            Status: [Object],
            Ec2InstanceAttributes: [Object],
            InstanceCollectionType: 'INSTANCE_GROUP',
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
            AutoScalingRole: 'EMR_AutoScaling_DefaultRole',
            ScaleDownBehavior: 'TERMINATE_AT_TASK_COMPLETION',
            EbsRootVolumeSize: 10,
            KerberosAttributes: {},
            ClusterArn: 'arn:aws:elasticmapreduce:us-east-1:123456654321:cluster/j-2RF0ACE2SIAWT',
            StepConcurrencyLevel: 1
        }
    }
];

const describeSecurityConfiguration = [
    {
        Name: 'sc-test-100-2',
        SecurityConfiguration: '{"EncryptionConfiguration":{"AtRestEncryptionConfiguration":{"LocalDiskEncryptionConfiguration":{"EncryptionKeyProviderType":"AwsKms","AwsKmsKey":"arn:aws:kms:us-east-1:123456654321:alias/test138","EnableEbsEncryption":true}},"EnableInTransitEncryption":false,"EnableAtRestEncryption":true}}',   
        CreationDateTime: '2020-09-17T09:39:01.657Z'
    },
    {
        Name: 'test-security-100',
        SecurityConfiguration: '{"EncryptionConfiguration":{"AtRestEncryptionConfiguration":{"S3EncryptionConfiguration":{"EncryptionMode":"SSE-S3"}},"EnableInTransitEncryption":false,"EnableAtRestEncryption":true}}',
        CreationDateTime: '2020-09-08T11:34:44.884Z'
    },
    {
        Name: 'test-sc-100',
        SecurityConfiguration: '{"EncryptionConfiguration":{"InTransitEncryptionConfiguration":{"TLSCertificateConfiguration":{"CertificateProviderType":"PEM","S3Object":"s3://test-bucket-sploit-100/cacert.zip"}},"AtRestEncryptionConfiguration":{"S3EncryptionConfiguration":{"EncryptionMode":"SSE-S3"}},"EnableInTransitEncryption":true,"EnableAtRestEncryption":true}}',
        CreationDateTime: '2020-09-06T09:50:42.222Z'
    }
];

const createCache = (listClusters, describeCluster, describeSecurityConfiguration) => {
    var clusterId = (listClusters && listClusters.length) ? listClusters[0].Id : null;
    var securtiyConfigurationName = (describeCluster &&
        describeCluster.Cluster &&
        describeCluster.Cluster.SecurityConfiguration) ? describeCluster.Cluster.SecurityConfiguration : null;

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
            describeSecurityConfiguration: {
                'us-east-1': {
                    [securtiyConfigurationName]: {
                        data: describeSecurityConfiguration
                    }
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        emr: {
            listClusters: {
                'us-east-1': {
                    err: {
                        message: 'error describing clusters'
                    },
                },
            },
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

describe('emrEncryptionAtRest', function () {
    describe('run', function () {
        it('should FAIL if encryption at rest for local disks is not enabled for EMR cluster', function (done) {
            const cache = createCache([listClusters[1]], describeCluster[0], describeSecurityConfiguration[1]);
            emrEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if no security configuration found for EMR cluster', function (done) {
            const cache = createCache([listClusters[1]], describeCluster[2], describeSecurityConfiguration[1]);
            emrEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if encryption at rest for local disks is enabled for EMR cluster', function (done) {
            const cache = createCache([listClusters[0]], describeCluster[2], describeSecurityConfiguration[0]);
            emrEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no EMR clusters found', function (done) {
            const cache = createCache([]);
            emrEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error querying for EMR clusters', function (done) {
            const cache = createErrorCache();
            emrEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for EMR clusters', function (done) {
            const cache = createNullCache();
            emrEncryptionAtRest.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
