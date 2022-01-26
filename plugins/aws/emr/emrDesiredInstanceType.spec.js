const expect = require('chai').expect;
const emrDesiredInstanceType = require('./emrDesiredInstanceType');

const listClusters = [
    {
        "Id": "j-2C3R1T3QB6HBQ",
        "Name": "My cluster",
        "Status": {
            "State": "RUNNING",
            "StateChangeReason": {},
            "Timeline": {
                "CreationDateTime": "2021-11-23T19:34:38.096000+05:00"
            }
        },
        "NormalizedInstanceHours": 0,
        "ClusterArn": "arn:aws:elasticmapreduce:us-east-1:000011112222:cluster/j-2C3R1T3QB6HBQ"
    },
    {
        "Id": "j-2GWDFSLQDWY54",
        "Name": "My cluster12",
        "Status": {
            "State": "RUNNING",
            "StateChangeReason": {
                "Code": "BOOTSTRAP_FAILURE",
                "Message": "On the master instance (i-07434010850e76576), application provisioning failed"
            },
            "Timeline": {
                "CreationDateTime": "2021-11-23T20:51:48.988000+05:00",
                "EndDateTime": "2021-11-23T21:02:45.793000+05:00"
            }
        },
        "NormalizedInstanceHours": 0,
        "ClusterArn": "arn:aws:elasticmapreduce:us-east-1:000011112222:cluster/j-2GWDFSLQDWY54"
    },
];

const listInstanceGroups = [
    {
        "InstanceGroups": [
            {
                "Id": "ig-2XSMNS4YJGOX4",
                "Name": "Core - 2",
                "Market": "ON_DEMAND",
                "InstanceGroupType": "CORE",
                "InstanceType": "c1.medium",
                "RequestedInstanceCount": 1,
                "RunningInstanceCount": 0,
                
            },
            {
                "Id": "ig-AIE5QGDR3LE1",
                "Name": "Master - 1",
                "Market": "ON_DEMAND",
                "InstanceGroupType": "MASTER",
                "InstanceType": "c1.medium",
                "RequestedInstanceCount": 1,
                "RunningInstanceCount": 0,
                
            },
        ],
    },
    {
        "InstanceGroups": [
            {
                "Id": "ig-2XSMNS4YJGOX4",
                "Name": "Core - 2",
                "Market": "ON_DEMAND",
                "InstanceGroupType": "CORE",
                "InstanceType": "m1.medium",
                "RequestedInstanceCount": 1,
                "RunningInstanceCount": 0,
               
            },
            {
                "Id": "ig-AIE5QGDR3LE1",
                "Name": "Master - 1",
                "Market": "ON_DEMAND",
                "InstanceGroupType": "MASTER",
                "InstanceType": "c1.medium",
                "RequestedInstanceCount": 1,
                "RunningInstanceCount": 0,
            },
        ],
    },
    {
        "InstanceGroups": [
            {
                "Id": "ig-2XSMNS4YJGOX4",
                "Name": "Core - 2",
                "Market": "ON_DEMAND",
                "InstanceGroupType": "CORE",
                "InstanceType": "c1.medium",
                "RequestedInstanceCount": 1,
                "RunningInstanceCount": 0,
            },
            {
                "Id": "ig-AIE5QGDR3LE1",
                "Name": "Master - 1",
                "Market": "ON_DEMAND",
                "InstanceGroupType": "MASTER",
                "InstanceType": "m1.medium",
                "RequestedInstanceCount": 1,
                "RunningInstanceCount": 0,
            },
        ],
    
    },
    {
        "InstanceGroups": [
            {
                "Id": "ig-2XSMNS4YJGOX4",
                "Name": "Core - 2",
                "Market": "ON_DEMAND",
                "InstanceGroupType": "CORE",
                "InstanceType": "m1.medium",
                "RequestedInstanceCount": 1,
                "RunningInstanceCount": 0,
            },
            {
                "Id": "ig-AIE5QGDR3LE1",
                "Name": "Master - 1",
                "Market": "ON_DEMAND",
                "InstanceGroupType": "MASTER",
                "InstanceType": "m1.medium",
                "RequestedInstanceCount": 1,
                "RunningInstanceCount": 0,
            },
        ],
    
    },
];

const createCache = (listClusters, listInstanceGroups) => {
    if (listClusters && listClusters.length) var id = listClusters[0].Id;
    return {
        emr: {
            listClusters: {
                'us-east-1': {
                    data: listClusters,
                },
            },
            listInstanceGroups: {
                'us-east-1': {
                    [id]: {
                        data: listInstanceGroups
                    }
                }
            }
        },
    };
};

const createErrorCache = () => {
    return {
        emr: {
            listClusters: {
                'us-east-1': {
                    err: {
                        message: 'error listing clusters'
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

describe('emrDesiredInstanceType', function () {
    describe('run', function () {
        it('should FAIL if master and core are not of desired instance type', function (done) {
            const cache = createCache([listClusters[0]], listInstanceGroups[3]);
            emrDesiredInstanceType.run(cache, { emr_desired_master_instance_type: 'c1.medium', emr_desired_core_instance_type: 'c1.medium' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if master instance is not of desired type', function (done) {
            const cache = createCache([listClusters[0]], listInstanceGroups[2]);
            emrDesiredInstanceType.run(cache, {emr_desired_master_instance_type: 'c1.medium', }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if core instance is not of desired type', function (done) {
            const cache = createCache([listClusters[1]], listInstanceGroups[1]);
            emrDesiredInstanceType.run(cache, {emr_desired_core_instance_type: 'c1.medium' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
        
        it('should PASS if master and core instances are of desired instance types', function (done) {
            const cache = createCache([listClusters[0]], listInstanceGroups[0]);
            emrDesiredInstanceType.run(cache, {emr_desired_core_instance_type: 'c1.medium', emr_desired_master_instance_type: 'c1.medium'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no clusters found', function (done) {
            const cache = createCache([], []);
            emrDesiredInstanceType.run(cache, {emr_desired_core_instance_type: 'c1.medium', emr_desired_master_instance_type: 'c1.medium'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error listing clusters', function (done) {
            const cache = createErrorCache();
            emrDesiredInstanceType.run(cache, {emr_desired_core_instance_type: 'c1.medium', emr_desired_master_instance_type: 'c1.medium'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for clusters', function (done) {
            const cache = createNullCache();
            emrDesiredInstanceType.run(cache, {emr_desired_core_instance_type: 'c1.medium', emr_desired_master_instance_type: 'c1.medium'}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should not return any results if settings are not provided', function (done) {
            const cache = createNullCache();
            emrDesiredInstanceType.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
