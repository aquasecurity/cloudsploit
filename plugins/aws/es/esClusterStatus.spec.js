const expect = require('chai').expect;
const esClusterStatus = require('./esClusterStatus');

const domainNames = [
    {
        "DomainName": "test-domain3-1"
    }
];

const esMetricStatistics = [
    {
        "Datapoints": [
            {
                "Timestamp": "2018-12-16T17:03:10Z",
                "Maximum": 1.333,
                "Unit": "Count"
            },
            {
                "Timestamp": "2018-12-16T18:03:10Z",
                "Maximum": 1.333,
                "Unit": "Count"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Maximum": 1.333,
                "Unit": "Count"
            },
        ]
    },
    {
        "Datapoints": [
            {
                "Timestamp": "2018-12-16T17:03:10Z",
                "Maximum": 0,
                "Unit": "Count"
            },
            {
                "Timestamp": "2018-12-16T18:03:10Z",
                "Maximum": 0,
                "Unit": "Count"
            },
            {
                "Timestamp": "2018-12-16T19:03:10Z",
                "Maximum": 0,
                "Unit": "Count"
            },
        ]
    },
    {
        "Datapoints": [
            {
                "Timestamp": "2018-12-16T17:03:10Z",
                "Unit": "Count"
            }
        ]
    }
]

const createCache = (domainNames, metrics) => {
    if (domainNames && domainNames.length) var name = domainNames[0].DomainName;
    return {
        es: {
            listDomainNames: {
                'us-east-1': {
                    data: domainNames,
                },
            },
        },
        cloudwatch: {
            getEsMetricStatistics: {
                'us-east-1': {
                    [name]: {
                        data: metrics
                    }
                }
            }
        },
    };
};

const createErrorCache = () => {
    return {
        es: {
            listDomainNames: {
                'us-east-1': {
                    err: {
                        message: 'error listing domain names'
                    },
                },
            },
        },
        cloudwatch: {
            getEsMetricStatistics: {
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
        es: {
            listDomainNames: {
                'us-east-1': null,
            },
        },
        cloudwatch: {
            getEsMetricStatistics: {
                'us-east-1': null
            },
        },
    };
};

describe('esClusterStatus', function () {
    describe('run', function () {
        it('should FAIL if metric count is greater than 1', function (done) {
            const cache = createCache([domainNames[0]], esMetricStatistics[0]);
            esClusterStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if metric count is lesser than 1', function (done) {
            const cache = createCache([domainNames[0]], esMetricStatistics[1]);
            esClusterStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
    
        it('should PASS if metric count is not part of the response', function (done) {
            const cache = createCache([domainNames[0]], esMetricStatistics[2]);
            esClusterStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
    
        it('should PASS if no domain names found', function (done) {
            const cache = createCache([]);
            esClusterStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list domain names', function (done) {
            const cache = createErrorCache();
            esClusterStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list domain names response not found', function (done) {
            const cache = createNullCache();
            esClusterStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
