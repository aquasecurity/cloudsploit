const expect = require('chai').expect;
const underutilizedredshiftCluster = require('./underutilizedRedshiftCluster');

const describeClusters = [
    {
        "ClusterIdentifier": "redshift-cluster-1",
        "NodeType": "dw.hs1.xlarge",
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
        "ClusterIdentifier": "redshift-cluster-1",
        "NodeType": "ds2.xlarge",
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



const redshiftMetricStatistics = [
    {
        "Datapoints": [
            {
                "Timestamp": "2018-12-16T17:03:10Z",
                "Average": 7.333,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T18:03:10Z",
                "Average": 40.333,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 16.333,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 24.333,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 14.333,
                "Unit": "Percent"
            },
        ]
    },
    {
        "Datapoints": [
            {
                "Timestamp": "2018-12-16T17:03:10Z",
                "Average": 2.99,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T18:03:10Z",
                "Average": 1.70,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 2.20,
                "Unit": "Percent"
            },
        ]
    }
]

const createCache = (cluster, metrics) => {
    if (cluster && cluster.length) var id = cluster[0].ClusterIdentifier;
    return {
        redshift: {
            describeClusters: {
                'us-east-1': {
                    data: cluster,
                },
            },
        },
        cloudwatch: {
            getredshiftMetricStatistics: {
                'us-east-1': {
                    [id]: {
                        data: metrics
                    }
                }
            }
        },
    };
};

const createErrorCache = () => {
    return {
        redshift: {
            describeClusters: {
                'us-east-1': {
                    err: {
                        message: 'error desribing cache clusters'
                    },
                },
            },
        },
        cloudwatch: {
            getredshiftMetricStatistics: {
                'us-east-1': {
                    err: {
                        message: 'error getting metric stats'
                    },
                }
            }
        },
    };
};

const createNullCache = () => {
    return {
        redshift: {
            describeClusters: {
                'us-east-1': null,
            },
        },
        cloudwatch: {
            getredshiftMetricStatistics: {
                'us-east-1': null
            },
        },
    };
};

describe('underutilizesredshiftCluster', function () {
    describe('run', function () {
        it('should PASS if the Redshift cluster cpu utilization is more than 5 percent', function (done) {
            const cache = createCache([describeClusters[0]], redshiftMetricStatistics[0]);
            underutilizedredshiftCluster.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Redshift cluster is not underutilized');
                done();
            });
        });

        it('should FAIL if the Redshift cpu utilization is less than 5 percent', function (done) {
            const cache = createCache([describeClusters[1]], redshiftMetricStatistics[1]);
            underutilizedredshiftCluster.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Redshift clusterfound', function (done) {
            const cache = createCache([]);
            underutilizedredshiftCluster.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Redshift clusters found');
                done();
            });
        });

        it('should UNKNOWN if unable to describe Redshift cluster', function (done) {
            const cache = createErrorCache();
            underutilizedredshiftCluster.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for Redshift clusters: ');
                done();
            });
        });

        it('should not return any results if describe EC2 Instance response not found', function (done) {
            const cache = createNullCache();
            underutilizedredshiftCluster.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        }); 
    });
});