var expect = require('chai').expect;
const reservedNodePaymentPending = require('./reservedNodePaymentPending');

const clusters = [
    {
        "ReservedCacheNodeId": "mynode",
        "ReservedCacheNodesOfferingId": "xxxxxxxxx-xxxxx-xxxxx-xxxx-xxxxxxxx71",
        "CacheNodeType": "cache.t3.small",
        "StartTime": "2019-12-06T02:50:44.003Z",
        "Duration": 31536000,
        "FixedPrice": 0.0,
        "UsagePrice": 0.0,
        "CacheNodeCount": 1,
        "ProductDescription": "redis",
        "OfferingType": "No Upfront",
        "State": "payment-pending",
        "RecurringCharges": [
            {
                "RecurringChargeAmount": 0.023,
                "RecurringChargeFrequency": "Hourly"
            }
        ],
        "ReservationARN": "arn:aws:elasticache:us-west-2:xxxxxxxxxxxx52:reserved-instance:mynode"
    },
    {
        "ReservedCacheNodeId": "mynode",
        "ReservedCacheNodesOfferingId": "xxxxxxxxx-xxxxx-xxxxx-xxxx-xxxxxxxx71",
        "CacheNodeType": "cache.t3.small",
        "StartTime": "2019-12-06T02:50:44.003Z",
        "Duration": 31536000,
        "FixedPrice": 0.0,
        "UsagePrice": 0.0,
        "CacheNodeCount": 1,
        "ProductDescription": "redis",
        "OfferingType": "No Upfront",
        "State": "payment-failed",
        "RecurringCharges": [
            {
                "RecurringChargeAmount": 0.023,
                "RecurringChargeFrequency": "Hourly"
            }
        ],
        "ReservationARN": "arn:aws:elasticache:us-west-2:xxxxxxxxxxxx52:reserved-instance:mynode"
    }
];

const createCache = (clusters) => {
    return {
        elasticache: {
            describeReservedCacheNodes: {
                'us-east-1': {
                    data: clusters,
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        elasticache: {
            describeReservedCacheNodes: {
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
        elasticache: {
            describeReservedCacheNodes: {
                'us-east-1': null,
            },
        },
    };
};

describe('reservedNodePaymentPending', function () {
    describe('run', function () {
        it('should FAIL if shown state payment is pending for ElastiCache reserved cache node', function (done) {
            const cache = createCache([clusters[0]]);
            reservedNodePaymentPending.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if payment state is not pending for ElastiCache reserved cache node', function (done) {
            const cache = createCache([clusters[1]]);
            reservedNodePaymentPending.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no ElastiCache reserved cache node found', function (done) {
            const cache = createCache([]);
            reservedNodePaymentPending.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error querying for ElastiCache reserved cache node', function (done) {
            const cache = createErrorCache();
            reservedNodePaymentPending.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for ElastiCache reserved cache node', function (done) {
            const cache = createNullCache();
            reservedNodePaymentPending.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
