const expect = require('chai').expect;
const idleRDSInstance = require('./idleRDSInstance');

const describeDBInstances=[
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
        StorageEncrypted: true,
        DBInstanceArn: 'arn:aws:rds:us-east-1:5566441122:db:test-1',
       
    },
    {
        DBInstanceIdentifier: 'test-2',
        DBInstanceClass: 'db.t3.micro',
        Engine: 'postgres',
        DBInstanceStatus: 'available',
        MasterUsername: 'Fatima',
        Endpoint: {
          Address: 'test-1.cscif9l5pu36.us-east-1.rds.amazonaws.com',
          Port: 5432,
          HostedZoneId: 'Z2R2ITUGPM61AM'
        },
        AvailabilityZone: 'us-east-1a',
        StorageEncrypted: true,
        DBInstanceArn: 'arn:aws:rds:us-east-1:5566441122:db:test-2',
       
    },
    {
        DBInstanceIdentifier: 'test-3',
        DBInstanceClass: 'db.t3.micro',
        Engine: 'mysql',
        DBInstanceStatus: 'available',
        MasterUsername: 'admin',
        Endpoint: {
          Address: 'test-1.cscif9l5pu36.us-east-1.rds.amazonaws.com',
          Port: 5432,
          HostedZoneId: 'Z2R2ITUGPM61AM'
        },
        AvailabilityZone: 'us-east-1a',
        StorageEncrypted: true,
        DBInstanceArn: 'arn:aws:rds:us-east-1:5566441122:db:test-3',
       
    }
]

const rdsMetricStatistics = [
    {
        "Datapoints": [
            {
                "Timestamp": "2018-12-16T17:03:10Z",
                "Average": 0,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T18:03:10Z",
                "Average": 0,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 0.333,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 0,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 0.333,
                "Unit": "Percent"
            },
        ]
    },
    {
        "Datapoints": [
            {
                "Timestamp": "2018-12-16T17:03:10Z",
                "Average": 94.99,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T18:03:10Z",
                "Average": 90.70,
                "Unit": "Percent"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Average": 99.20,
                "Unit": "Percent"
            },
        ]
    }
]

const createCache = (instance, metrics) => {
    if (instance && instance.length) var id = instance[0].DBInstanceIdentifier;
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    data: instance,
                },
            },
        },
        cloudwatch: {
            getRdsMetricStatistics: {
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
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    err: {
                        message: 'error desribing cache clusters'
                    },
                },
            },
        },
        cloudwatch: {
            getRdsMetricStatistics: {
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
        rds: {
            describeDBInstances: {
                'us-east-1': null,
            },
        },
        cloudwatch: {
            getRdsMetricStatistics: {
                'us-east-1': null
            },
        },
    };
};

describe('idleRDSInstance', function () {
    describe('run', function () {
        it('should PASS if the RDS Instance cpu utilization is more than 1.0 percent', function (done) {
            const cache = createCache([describeDBInstances[0]], rdsMetricStatistics[1]);
            idleRDSInstance.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if the RDS Instance cpu utilization is less than or equal to 1.0 percent', function (done) {
            const cache = createCache([describeDBInstances[1]], rdsMetricStatistics[0]);
            idleRDSInstance.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no RDS Instance found', function (done) {
            const cache = createCache([]);
            idleRDSInstance.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No RDS instance found');
                done();
            });
        });

        it('should UNKNOWN if unable to describe RDS Instance', function (done) {
            const cache = createErrorCache();
            idleRDSInstance.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for RDS instance: ');
                done();
            });
        });

        it('should not return any results if describe RDS Instance response not found', function (done) {
            const cache = createNullCache();
            idleRDSInstance.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        }); 
    });
});
