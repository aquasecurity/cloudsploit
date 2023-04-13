const expect = require('chai').expect;
const osClusterStatus = require('./opensearchClusterStatus');

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
        opensearch: {
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
        opensearch: {
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
        opensearch: {
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

describe('osClusterStatus', function () {
    describe('run', function () {
        it('should FAIL if metric count is greater than 1', function (done) {
            const cache = createCache([domainNames[0]], esMetricStatistics[0]);
            osClusterStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.includes('OpenSearch Domain is unhealthy');
                done();
            });
        });

        it('should PASS if metric count is lesser than 1', function (done) {
            const cache = createCache([domainNames[0]], esMetricStatistics[1]);
            osClusterStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.includes('OpenSearch Domain is healthy');
                done();
            });
        });
    
        it('should PASS if metric count is not part of the response', function (done) {
            const cache = createCache([domainNames[0]], esMetricStatistics[2]);
            osClusterStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.includes('OpenSearch Domain is healthy');
                done();
            });
        });
    
        it('should PASS if no domain names found', function (done) {
            const cache = createCache([]);
            osClusterStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.includes('No OpenSearch domains found');
                done();
            });
        });

        it('should UNKNOWN if unable to list domain names', function (done) {
            const cache = createErrorCache();
            osClusterStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.includes('Unable to query for OpenSearch domains:');
                done();
            });
        });

        it('should not return any results if list domain names response not found', function (done) {
            const cache = createNullCache();
            osClusterStatus.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
