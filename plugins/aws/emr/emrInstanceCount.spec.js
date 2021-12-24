var expect = require('chai').expect;
const emrInstanceCount = require('./emrInstanceCount');

const listClusters = [
    {
        "Id": "j-2WEMA6IZNEA1R",
        "Name": "My cluster",
        "Status": {
            "State": "TERMINATED_WITH_ERRORS",
            "StateChangeReason": {
                "Code": "BOOTSTRAP_FAILURE",
                "Message": "On the master instance (i-02dd18e1bef968b9a), application provisioning failed"
            },
            "Timeline": {
                "CreationDateTime": "2021-11-24T18:54:26.015000+05:00",
                "EndDateTime": "2021-11-24T19:14:04.676000+05:00"
            }
        },
        "NormalizedInstanceHours": 0,
        "ClusterArn": "arn:aws:elasticmapreduce:us-east-1:000111222333:cluster/j-2WEMA6IZNEA1R"
    },
];

const listInstanceGroups= [
    {
        "InstanceGroups": [
            {
                "Id": "ig-2XSMNS4YJGOX4",
                "Name": "Core - 2",
                "Market": "ON_DEMAND",
                "InstanceGroupType": "CORE",
                "InstanceType": "c1.medium",
                "RequestedInstanceCount": 1,
                "RunningInstanceCount": 2,

            },
            {
                "Id": "ig-AIE5QGDR3LE1",
                "Name": "Master - 1",
                "Market": "ON_DEMAND",
                "InstanceGroupType": "MASTER",
                "InstanceType": "c1.medium",
                "RequestedInstanceCount": 2,
                "RunningInstanceCount": 3,

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
                "RunningInstanceCount": 2,

            },
            {
                "Id": "ig-AIE5QGDR3LE1",
                "Name": "Master - 1",
                "Market": "ON_DEMAND",
                "InstanceGroupType": "MASTER",
                "InstanceType": "c1.medium",
                "RequestedInstanceCount": 1,
                "RunningInstanceCount": 4,
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
                "RunningInstanceCount": 2,
            },
            {
                "Id": "ig-AIE5QGDR3LE1",
                "Name": "Master - 1",
                "Market": "ON_DEMAND",
                "InstanceGroupType": "MASTER",
                "InstanceType": "m1.medium",
                "RequestedInstanceCount": 1,
                "RunningInstanceCount": 1,
            },
        ]
    },
];

const createCache = (instances, listInstanceGroups) => {
    if (listClusters && listClusters.length) var id = listClusters[0].Id;
    return {
        emr:{
            listClusters: {
                'us-east-1': {
                    data: instances
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
        emr:{
            listClusters: {
                'us-east-1': {
                    err: {
                        message: 'error describing instances'
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        emr:{
            listClusters: {
                'us-east-1': null,
            },
        },
    };
};


describe('emrInstanceCount', function () {
    describe('run', function () {
        it('should PASS if instances are within the regional and global expected count', function (done) {
            const cache = createCache([listClusters[0]], listInstanceGroups[2]);
            var settings = {
                emr_instance_count_global_threshold: 2,
                emr_instance_count_regional_threshold: 1
            };

            emrInstanceCount.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if instances are not in the regional expected count', function (done) {
            const cache = createCache([listClusters[0]], listInstanceGroups[1]);
            var settings = {
                emr_instance_count_global_threshold: 2,
                emr_instance_count_regional_threshold: 1
            };

            emrInstanceCount.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if instances are not in the global expected count', function (done) {
            const cache = createCache([listClusters[0]], listInstanceGroups[0]);
            var settings = {
                emr_instance_count_global_threshold: 2,
                emr_instance_count_regional_threshold: 2
            };

            emrInstanceCount.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if instances are not in the regional and global expected count', function (done) {
            const cache = createCache([listClusters[0]], listInstanceGroups[3]);
            var settings = {
                emr_instance_count_global_threshold: 1,
                emr_instance_count_regional_threshold: 1
            };

            emrInstanceCount.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no instances found', function (done) {
            const cache = createCache([]);
            emrInstanceCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if unable to list instance groups', function (done) {
            const cache = createErrorCache();
            emrInstanceCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should PASS if instance groups response not found', function (done) {
            const cache = createNullCache();
            emrInstanceCount.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
    });
});