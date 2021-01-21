var expect = require('chai').expect;
const redshiftClusterDefaultPort = require('./redshiftClusterDefaultPort');

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
            "Address": "redshift-cluster-2.cks44thktt7l.us-east-1.redshift.amazonaws.com",
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
    }
];


const createCache = (clusters) => {
    return {
        redshift:{
            describeClusters: {
                'us-east-1': {
                    data: clusters
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        redshift:{
            describeClusters: {
                'us-east-1': {
                    err: {
                        message: 'error describing redshift clusters'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        redshift:{
            describeClusters: {
                'us-east-1': null,
            },
        },
    };
};

describe('redshiftClusterDefaultPort', function () {
    describe('run', function () {
        it('should PASS if Redshift cluster is using default "5439" port', function (done) {
            const cache = createCache([describeClusters[0]]);
            redshiftClusterDefaultPort.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Redshift cluster is not using default "5439" port', function (done) {
            const cache = createCache([describeClusters[1]]);
            redshiftClusterDefaultPort.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Redshift clusters found', function (done) {
            const cache = createCache([]);
            redshiftClusterDefaultPort.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe clusters', function (done) {
            const cache = createErrorCache();
            redshiftClusterDefaultPort.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe clusters response not found', function (done) {
            const cache = createNullCache();
            redshiftClusterDefaultPort.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});